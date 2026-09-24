// Package awsadapt holds the only code in the service that imports the AWS
// SDK.
//
// Every business package declares a narrow interface for the slice of AWS it
// needs, and this package is the single implementation of each. Concentrating
// the SDK here is what makes "no unit test touches AWS" a mechanical property
// rather than a habit -- TestPackages_DoNotImportAWSSDK asserts it.
package awsadapt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/samma-io/detection-engine/internal/engine"
	"github.com/samma-io/detection-engine/internal/publisher"
)

// ---------------------------------------------------------------- SQS input

// Queue reads the per-source filtered queue.
type Queue struct {
	Client   *sqs.Client
	QueueURL string
}

// Receive long-polls for messages.
//
// ApproximateReceiveCount is requested because it is the only way to see a
// message walking toward the DLQ. Depth alone does not show it: a message held
// by the visibility heartbeat for half an hour still reports a count of 1.
func (q *Queue) Receive(ctx context.Context, max int32, waitSeconds int32) ([]engine.Message, error) {
	out, err := q.Client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(q.QueueURL),
		MaxNumberOfMessages: max,
		WaitTimeSeconds:     waitSeconds,
		MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{
			sqstypes.MessageSystemAttributeNameApproximateReceiveCount,
		},
	})
	if err != nil {
		return nil, err
	}

	msgs := make([]engine.Message, 0, len(out.Messages))
	for _, m := range out.Messages {
		count := 0
		if v, ok := m.Attributes[string(sqstypes.MessageSystemAttributeNameApproximateReceiveCount)]; ok {
			count, _ = strconv.Atoi(v)
		}
		msgs = append(msgs, engine.Message{
			MessageID:     aws.ToString(m.MessageId),
			ReceiptHandle: aws.ToString(m.ReceiptHandle),
			Body:          aws.ToString(m.Body),
			ReceiveCount:  count,
		})
	}
	return msgs, nil
}

// Delete removes a message whose work is complete.
func (q *Queue) Delete(ctx context.Context, receiptHandle string) error {
	_, err := q.Client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(q.QueueURL),
		ReceiptHandle: aws.String(receiptHandle),
	})
	return err
}

// ExtendVisibility slides a message's visibility window.
//
// SQS sets the timeout relative to now rather than to the original receive, so
// repeated calls slide the window instead of accumulating. Passing zero
// releases the message immediately, which is how a shutdown hands work back
// without making the next task wait out the remaining window.
func (q *Queue) ExtendVisibility(ctx context.Context, receiptHandle string, seconds int32) error {
	_, err := q.Client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl:          aws.String(q.QueueURL),
		ReceiptHandle:     aws.String(receiptHandle),
		VisibilityTimeout: seconds,
	})
	return err
}

// ---------------------------------------------------------------- SQS output

// AlertQueue publishes to the shared detections queue.
type AlertQueue struct {
	Client   *sqs.Client
	QueueURL string
}

// SendBatch sends up to ten entries and returns the per-entry rejections.
//
// SendMessageBatch answers HTTP 200 with a Failed list, so the rejections are
// returned as data rather than folded into the error. Treating a 200 as
// success is a silent alert loss.
func (a *AlertQueue) SendBatch(ctx context.Context, entries []publisher.Outbound) ([]publisher.Rejection, error) {
	in := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String(a.QueueURL),
		Entries:  make([]sqstypes.SendMessageBatchRequestEntry, 0, len(entries)),
	}
	for _, e := range entries {
		in.Entries = append(in.Entries, sqstypes.SendMessageBatchRequestEntry{
			Id:          aws.String(e.ID),
			MessageBody: aws.String(e.Body),
		})
	}

	out, err := a.Client.SendMessageBatch(ctx, in)
	if err != nil {
		return nil, err
	}

	rejections := make([]publisher.Rejection, 0, len(out.Failed))
	for _, f := range out.Failed {
		rejections = append(rejections, publisher.Rejection{
			ID:          aws.ToString(f.Id),
			Code:        aws.ToString(f.Code),
			Message:     aws.ToString(f.Message),
			SenderFault: f.SenderFault,
		})
	}
	return rejections, nil
}

// ---------------------------------------------------------------- S3

// Objects reads log objects and writes evidence.
type Objects struct {
	Client *s3.Client
}

// Size returns an object's length without fetching it, so an oversized object
// can be refused before it is streamed.
func (o *Objects) Size(ctx context.Context, bucket, key string) (int64, error) {
	out, err := o.Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return 0, err
	}
	return aws.ToInt64(out.ContentLength), nil
}

// Get opens an object for streaming. The caller closes it.
func (o *Objects) Get(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	out, err := o.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

// Put writes an object, used for the evidence store.
func (o *Objects) Put(ctx context.Context, bucket, key string, body []byte) error {
	_, err := o.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   strings.NewReader(string(body)),
	})
	return err
}

// List returns every key under a prefix, following pagination.
func (o *Objects) List(ctx context.Context, bucket, prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(o.Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			keys = append(keys, aws.ToString(obj.Key))
		}
	}
	return keys, nil
}

// IsNotFound reports whether an error means the object does not exist.
//
// Distinguishing this matters: a missing object -- lifecycle expiry, or a
// replayed notification for something long gone -- can never succeed on
// retry, so it must be recorded and released rather than sent round the
// redelivery loop three times first.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *s3types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	// HeadObject returns a bare 404 with no typed shape.
	return strings.Contains(err.Error(), "StatusCode: 404")
}

// Interface assertions, so a signature drift is a compile error here rather
// than a wiring error in main.
var (
	_ engine.Queue       = (*Queue)(nil)
	_ engine.ObjectStore = (*Objects)(nil)
	_ publisher.Sender   = (*AlertQueue)(nil)
)

var _ = fmt.Sprintf
