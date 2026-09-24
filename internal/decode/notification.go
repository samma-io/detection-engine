// Package decode turns SQS message bodies into object references, and object
// bodies into a stream of records.
package decode

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ObjectRef is one object named by an S3 event notification.
type ObjectRef struct {
	Bucket string
	Key    string
	Size   int64
}

// Notification is the decoded form of one SQS message body.
type Notification struct {
	// Objects is empty for a control message such as s3:TestEvent.
	Objects []ObjectRef

	// TestEvent reports that this was S3's configuration probe. It carries no
	// objects and must be deleted rather than retried forever.
	TestEvent bool
}

// s3Event is the part of the S3 event notification we use.
//
// Declared here rather than taken from aws-lambda-go's events package so that
// decoding does not pull in the whole Lambda event surface for a service that
// is not a Lambda.
type s3Event struct {
	Records []struct {
		EventName string `json:"eventName"`
		S3        struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key  string `json:"key"`
				Size int64  `json:"size"`
			} `json:"object"`
		} `json:"s3"`
	} `json:"Records"`
}

// testEvent is the probe S3 delivers once when a notification is configured.
type testEvent struct {
	Service string `json:"Service"`
	Event   string `json:"Event"`
	Bucket  string `json:"Bucket"`
}

// Notification decodes an SQS message body.
//
// A body that will not decode is an error, never a silent skip: the caller
// deletes the message on success, so returning cleanly here would drop the
// notification and lose the object with nothing anywhere recording that it
// existed. The object itself stays in S3, but nothing would ever look at it.
func ParseNotification(body []byte) (Notification, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return Notification{}, fmt.Errorf("empty message body")
	}

	// s3:TestEvent first: it has no Records at all, so trying the object
	// shape first would report "no records" for a message that is perfectly
	// well-formed and simply is not about an object.
	var probe testEvent
	if err := json.Unmarshal([]byte(trimmed), &probe); err == nil && probe.Event == "s3:TestEvent" {
		return Notification{TestEvent: true}, nil
	}

	var event s3Event
	if err := json.Unmarshal([]byte(trimmed), &event); err != nil {
		return Notification{}, fmt.Errorf("body is not an S3 event notification: %w", err)
	}
	if event.Records == nil {
		return Notification{}, fmt.Errorf("body has no Records array")
	}

	objects := make([]ObjectRef, 0, len(event.Records))
	for i, r := range event.Records {
		if r.S3.Bucket.Name == "" || r.S3.Object.Key == "" {
			return Notification{}, fmt.Errorf("record %d has no bucket or key", i)
		}
		key, err := DecodeKey(r.S3.Object.Key)
		if err != nil {
			return Notification{}, fmt.Errorf("record %d: %w", i, err)
		}
		objects = append(objects, ObjectRef{
			Bucket: r.S3.Bucket.Name,
			Key:    key,
			Size:   r.S3.Object.Size,
		})
	}
	return Notification{Objects: objects}, nil
}

// DecodeKey undoes the URL encoding S3 applies to object keys in event
// notifications.
//
// Two traps live here. S3 encodes the key with form encoding, so "+" means a
// literal space and not a plus sign -- url.PathUnescape would leave it as "+"
// and every GetObject on a key containing a space would 404. And the filtered
// bucket's Hive-style partition means every single key contains "date%3D",
// so a service that forgot to unescape would fail on every object rather than
// on an unlucky few, which at least fails loudly.
func DecodeKey(raw string) (string, error) {
	key, err := url.QueryUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("object key %q is not valid URL encoding: %w", raw, err)
	}
	return key, nil
}
