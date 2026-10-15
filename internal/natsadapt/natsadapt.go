// Package natsadapt holds the only code in the service that imports the NATS
// client. It is the Kubernetes counterpart of awsadapt: the same engine.Queue
// and publisher.Sender interfaces, backed by JetStream instead of SQS.
//
// The transport contract is in samma-io/aws-siem
// docs/contracts/detection-alert-v1.md, section "NATS transport".
package natsadapt

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/engine"
	"github.com/samma-io/detection-engine/internal/publisher"
)

// MaxWait caps one fetch. JetStream fetches cannot be cancelled by a context,
// so this is also the longest a worker takes to notice shutdown.
const MaxWait = 5 * time.Second

// Fetcher is the slice of a JetStream consumer the queue needs.
type Fetcher interface {
	Fetch(batch int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error)
}

// Logs reads one lane's records from a durable pull consumer.
//
// The receipt handle is the stream sequence. A redelivery carries the same
// sequence, so the pending map stays bounded by what is in flight even though
// a Transient disposition never removes its entry.
type Logs struct {
	Consumer Fetcher
	Stream   string

	mu      sync.Mutex
	pending map[string]jetstream.Msg
}

// Receive fetches up to max messages, waiting at most waitSeconds (capped at
// MaxWait).
func (l *Logs) Receive(ctx context.Context, max int32, waitSeconds int32) ([]engine.Message, error) {
	wait := time.Duration(waitSeconds) * time.Second
	if wait <= 0 || wait > MaxWait {
		wait = MaxWait
	}
	batch, err := l.Consumer.Fetch(int(max), jetstream.FetchMaxWait(wait))
	if err != nil {
		return nil, err
	}

	var out []engine.Message
	for m := range batch.Messages() {
		md, err := m.Metadata()
		if err != nil {
			// Without metadata there is no stream sequence and so no stable
			// alert id. Leave it unacknowledged; it is redelivered after
			// AckWait and counted against MaxDeliver.
			continue
		}
		handle := strconv.FormatUint(md.Sequence.Stream, 10)
		l.remember(handle, m)
		out = append(out, engine.Message{
			MessageID:     m.Subject() + "/" + handle,
			ReceiptHandle: handle,
			ReceiveCount:  int(md.NumDelivered),
			Inline: &engine.Inline{
				Ref: decode.ObjectRef{
					Bucket: "nats:" + l.Stream,
					Key:    m.Subject() + "/" + handle,
					Size:   int64(len(m.Data())),
				},
				Body: m.Data(),
			},
		})
	}
	if err := batch.Error(); err != nil && !errors.Is(err, jetstream.ErrNoMessages) &&
		!errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return out, err
	}
	return out, nil
}

// Delete acknowledges the message. It waits for the server's confirmation,
// because an ack lost in flight is a duplicate replay that nothing reports.
func (l *Logs) Delete(ctx context.Context, receiptHandle string) error {
	m, ok := l.take(receiptHandle)
	if !ok {
		return fmt.Errorf("no message in flight for sequence %s", receiptHandle)
	}
	return m.DoubleAck(ctx)
}

// ExtendVisibility resets the consumer's AckWait. Zero hands the message back
// at once, as SQS does with a zero visibility timeout.
func (l *Logs) ExtendVisibility(_ context.Context, receiptHandle string, seconds int32) error {
	if seconds == 0 {
		m, ok := l.take(receiptHandle)
		if !ok {
			return nil
		}
		return m.Nak()
	}
	l.mu.Lock()
	m, ok := l.pending[receiptHandle]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("no message in flight for sequence %s", receiptHandle)
	}
	return m.InProgress()
}

func (l *Logs) remember(handle string, m jetstream.Msg) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil {
		l.pending = make(map[string]jetstream.Msg)
	}
	l.pending[handle] = m
}

func (l *Logs) take(handle string) (jetstream.Msg, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.pending[handle]
	delete(l.pending, handle)
	return m, ok
}

// Publisher is the slice of JetStream the alert sender needs.
type Publisher interface {
	Publish(ctx context.Context, subject string, payload []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// Alerts publishes alerts to the lane's alert subject.
//
// The alert id is sent as Nats-Msg-Id, so a replay inside the stream's
// duplicate window is dropped by the server rather than delivered twice.
type Alerts struct {
	JS      Publisher
	Subject string
}

var _ publisher.Sender = (*Alerts)(nil)

// SendBatch publishes each entry and waits for its acknowledgement. A failed
// publish is reported as retryable: JetStream has no notion of a message that
// is unacceptable in itself, short of the size limit, which the batcher
// already enforces below.
func (a *Alerts) SendBatch(ctx context.Context, entries []publisher.Outbound) ([]publisher.Rejection, error) {
	var rejected []publisher.Rejection
	for _, e := range entries {
		if _, err := a.JS.Publish(ctx, a.Subject, []byte(e.Body), jetstream.WithMsgID(e.AlertID)); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			rejected = append(rejected, publisher.Rejection{
				ID: e.ID, Code: "publish", Message: err.Error(), SenderFault: false,
			})
		}
	}
	return rejected, nil
}
