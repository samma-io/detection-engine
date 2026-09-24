// Package alert defines the single message shape published to the shared
// detections queue.
package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/samma-io/detection-engine/internal/rules"
)

// SchemaVersion is carried on every alert so a consumer can branch on shape
// rather than guess from which fields are present.
const SchemaVersion = "detection.alert.v1"

// Alert is one rule firing on one event.
type Alert struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	AlertedAt     time.Time `json:"alerted_at"`

	// LogSource is the deployment that produced this alert.
	//
	// Deliberately not called "source": Vector stamps a "source" field inside
	// every filtered event, so a top-level "source" here would mean one thing
	// in the envelope and another one level down, and `jq .source` would
	// return a different type depending on which the reader had in mind.
	LogSource string `json:"log_source"`

	Rule       rules.Match `json:"rule"`
	Provenance Provenance  `json:"provenance"`

	// Event is the matched record, re-marshalled from the decoded map rather
	// than passed through as the original bytes.
	//
	// That is not incidental. SQS rejects message bodies containing invalid
	// UTF-8 with InvalidMessageContents, and it rejects the whole request, so
	// one bad byte in a user agent would take down every alert batched with
	// it. Marshalling from the map coerces invalid UTF-8 to U+FFFD and escapes
	// control characters, which is exactly the sanitisation needed. Some
	// filtered lanes derive from regex-parsed raw log lines, so this is
	// reachable in production, not theoretical.
	//
	// Nil when Truncated is set.
	Event map[string]any `json:"event,omitempty"`

	// Truncated reports that Event was dropped because the alert exceeded the
	// SQS message limit. Provenance still names the object and the record
	// index, so the original is recoverable by hand.
	Truncated bool `json:"truncated,omitempty"`

	// EventSHA256 digests the event as marshalled here. It is not part of ID
	// -- see New -- but it lets a consumer group identical events and survives
	// truncation.
	EventSHA256 string `json:"event_sha256,omitempty"`
	EventBytes  int    `json:"event_bytes,omitempty"`
}

// Provenance is where the event came from, in enough detail to fetch it again.
type Provenance struct {
	Bucket     string `json:"bucket"`
	Key        string `json:"key"` // decoded, not URL-encoded
	EventIndex int    `json:"event_index"`

	// SQSMessageID is the delivery that produced this alert. It changes on
	// redelivery, which is exactly why it is not part of ID.
	SQSMessageID string `json:"sqs_message_id,omitempty"`
}

// Input is what New needs to build an alert.
type Input struct {
	Rule         rules.Match
	LogSource    string
	Bucket       string
	Key          string
	EventIndex   int
	SQSMessageID string
	Event        map[string]any
	Now          time.Time
}

// New builds an alert with a deterministic id.
func New(in Input) (Alert, error) {
	body, err := json.Marshal(in.Event)
	if err != nil {
		return Alert{}, fmt.Errorf("marshalling event: %w", err)
	}
	sum := sha256.Sum256(body)

	return Alert{
		SchemaVersion: SchemaVersion,
		ID:            ID(in.Rule.RuleID, in.LogSource, in.Bucket, in.Key, in.EventIndex),
		AlertedAt:     in.Now.UTC(),
		LogSource:     in.LogSource,
		Rule:          in.Rule,
		Provenance: Provenance{
			Bucket:       in.Bucket,
			Key:          in.Key,
			EventIndex:   in.EventIndex,
			SQSMessageID: in.SQSMessageID,
		},
		Event:       in.Event,
		EventSHA256: hex.EncodeToString(sum[:]),
		EventBytes:  len(body),
	}, nil
}

// ID derives the alert identifier from the finding, not from the delivery.
//
// Every path into this service is at-least-once: SQS redelivers, S3 raises
// duplicate ObjectCreated notifications, and an object abandoned mid-way by a
// SIGTERM is reprocessed from the start. All of those must produce a
// byte-identical id, or each one turns into a duplicate ticket downstream.
//
// AlertedAt is excluded because it is the clock, and the same finding replayed
// an hour later is the same finding. The SQS message id is excluded for the
// same reason -- it is a property of the delivery. The ruleset contents are
// excluded too, which is the less obvious one: keying on them would change
// every id whenever an unrelated rule was added to the bucket, so a routine
// rule deploy would re-alert on everything still in the queue.
//
// The zero-byte separator is not decoration. Without it, ("ab", "c") and
// ("a", "bc") hash identically, and rule ids and S3 keys are exactly the kind
// of adjacent free-text fields where that collides.
//
// Consumers must upsert on this id rather than insert; that is the whole point.
func ID(ruleID, logSource, bucket, key string, eventIndex int) string {
	h := sha256.New()
	for _, part := range []string{
		SchemaVersion, ruleID, logSource, bucket, key, strconv.Itoa(eventIndex),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "det_" + hex.EncodeToString(h.Sum(nil))
}

// Truncate drops the event body, keeping everything that identifies the alert.
//
// Used when an alert would exceed the SQS per-message limit. The rule metadata
// and the provenance are what triage reads first, and the provenance is enough
// to pull the original record out of S3, so dropping the body is a real loss
// but a recoverable one. Dropping the alert would not be.
//
// The id is unchanged, so a retry that truncates where the first attempt did
// not still deduplicates to one alert.
func (a Alert) Truncate() Alert {
	a.Event = nil
	a.Truncated = true
	return a
}

// Encode marshals the alert for the queue.
func (a Alert) Encode() ([]byte, error) { return json.Marshal(a) }
