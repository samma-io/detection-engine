// Package engine is the receive-decode-evaluate-publish-delete loop.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/samma-io/detection-engine/internal/alert"
	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/metrics"
	"github.com/samma-io/detection-engine/internal/rules"
	"github.com/samma-io/detection-engine/internal/source"
)

// minDecodeErrors is the absolute grace before the decode error ratio applies.
//
// Without it, a one-record object whose single record is corrupt has a 100%
// error rate and would fail the object -- the ratio only means anything once
// there is a sample to take a ratio of.
const minDecodeErrors = 10

// Message is the queue-shaped part of an SQS message.
type Message struct {
	MessageID     string
	ReceiptHandle string
	Body          string

	// ReceiveCount is ApproximateReceiveCount. It exists to be observed: it is
	// how a message walking toward the DLQ becomes visible before it arrives.
	ReceiveCount int
}

// Queue is the slice of SQS the engine consumes.
//
// Delete and ExtendVisibility are separate methods rather than one Ack
// because their failure modes are opposite: a failed Delete costs duplicate
// work, a failed ExtendVisibility risks concurrent work.
type Queue interface {
	Receive(ctx context.Context, max int32, waitSeconds int32) ([]Message, error)
	Delete(ctx context.Context, receiptHandle string) error
	ExtendVisibility(ctx context.Context, receiptHandle string, seconds int32) error
}

// ObjectStore reads log objects.
//
// Get returns a ReadCloser, not a []byte: Vector writes ~10 MB compressed
// batches that decompress to a hundred megabytes or more, so a resident object
// would OOM the task -- and on Fargate an OOM is a SIGKILL, meaning no log
// line, no metric, and a redelivery that OOMs identically.
type ObjectStore interface {
	Size(ctx context.Context, bucket, key string) (int64, error)
	Get(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// AlertSink accumulates alerts and makes them durable.
//
// Nothing added is durable until a Flush returns nil.
type AlertSink interface {
	Add(ctx context.Context, a alert.Alert) error
	Flush(ctx context.Context) error
	Published() int
}

// Disposition is what should happen to a message.
//
// There is deliberately no Poison state. SQS already has a dead-letter queue
// with fourteen days of retention, so a permanently unprocessable message
// becomes its own evidence by not being deleted: three redeliveries later it
// is parked in filtered-dlq with its body intact. Writing a copy to S3 first
// would buy nothing and would need an evidence bucket that must not be the
// filtered bucket -- a poison write into a notified prefix is an infinite,
// billable loop.
type Disposition int

const (
	// Accepted: every alert for the message is durable. Delete it.
	Accepted Disposition = iota
	// Skipped: nothing to do (an s3:TestEvent). Delete it.
	Skipped
	// Transient: nothing durable. Do NOT delete; let SQS redeliver.
	Transient
)

func (d Disposition) String() string {
	switch d {
	case Accepted:
		return "accepted"
	case Skipped:
		return "skipped"
	case Transient:
		return "transient"
	default:
		return "unknown"
	}
}

// Limits bound the work one message may cost.
type Limits struct {
	MaxObjectBytes     int64
	MaxObjectDuration  time.Duration
	MaxLineBytes       int
	MaxDecodeErrorRate float64
	MaxAlertsPerObject int
}

// Processor handles one message at a time. It never touches the queue:
// deletion belongs to Run, so the "delete only after every alert is durable"
// rule is stated in exactly one place instead of being re-derived at each of
// a dozen early returns.
type Processor struct {
	Source  source.Source
	Objects ObjectStore
	Rules   *rules.Set
	NewSink func() AlertSink
	Limits  Limits
	Now     func() time.Time
	Log     *slog.Logger
}

// Handle processes exactly one message and reports what should happen to it.
func (p *Processor) Handle(ctx context.Context, msg Message) (disp Disposition) {
	metrics.MessagesReceived.Inc()
	metrics.ReceiveCount.Observe(float64(msg.ReceiveCount))
	defer func() { metrics.MessageDisposition.WithLabelValues(disp.String()).Inc() }()

	// sigma-go panics rather than erroring on several inputs, and the rules
	// package already recovers per rule. This is the backstop for everything
	// else: in a single-process task an unrecovered panic means the task dies,
	// ECS restarts it, SQS redelivers the same message, and the deployment
	// crash-loops with detection off for the entire source. Containing it to
	// one message costs three redeliveries and a DLQ entry.
	defer func() {
		if r := recover(); r != nil {
			metrics.Panics.Inc()
			p.Log.Error("panic processing message",
				"msg_id", msg.MessageID, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			disp = Transient
		}
	}()

	notif, err := decode.ParseNotification([]byte(msg.Body))
	if err != nil {
		// Not deleted. The body will not parse on redelivery either, so it
		// walks to the DLQ, where the notification survives with its body
		// intact and someone can see it. Deleting here would lose the
		// reference to an object that is still sitting in S3 with nothing
		// recording that it was never examined.
		metrics.Poison.WithLabelValues("envelope").Inc()
		p.Log.Error("undecodable message body, not deleting",
			"msg_id", msg.MessageID, "receive_count", msg.ReceiveCount, "err", err)
		return Transient
	}
	if notif.TestEvent {
		// S3 sends exactly one of these when a notification is configured.
		// It is neither data nor an error; deleting it is correct, and
		// treating it as malformed would park it in the DLQ on the first
		// deploy of every new lane.
		metrics.TestEvents.Inc()
		p.Log.Info("s3:TestEvent", "msg_id", msg.MessageID)
		return Skipped
	}

	// One notification can name several objects. All must be durable before
	// the message is deleted, so a failure on any one aborts the message.
	// Redelivery reprocesses the objects that already succeeded, which costs
	// duplicate alerts -- absorbed by the deterministic alert id. SQS has no
	// per-record acknowledgement, so there is no third option.
	for _, obj := range notif.Objects {
		if d := p.object(ctx, msg, obj); d != Accepted {
			return d
		}
	}
	return Accepted
}

// object streams one S3 object and publishes every alert it produces.
func (p *Processor) object(ctx context.Context, msg Message, obj decode.ObjectRef) Disposition {
	log := p.Log.With("msg_id", msg.MessageID, "bucket", obj.Bucket, "key", obj.Key)
	start := p.Now()

	if !strings.HasPrefix(obj.Key, p.Source.KeyPrefix()) {
		// The queue is subscribed to the wrong notification. Evaluating this
		// source's rules against another source's events would produce
		// confident nonsense, so refuse and let it reach the DLQ where the
		// misconfiguration is visible.
		metrics.Poison.WithLabelValues("wrong_prefix").Inc()
		log.Error("object is not under this source's prefix, not deleting",
			"want_prefix", p.Source.KeyPrefix())
		return Transient
	}

	// A per-object deadline independent of the visibility heartbeat. The
	// heartbeat will extend happily forever; without this bound one
	// pathological object pins a worker until somebody notices, and
	// "detection is six hours behind" is not a page anybody gets.
	ctx, cancel := context.WithTimeout(ctx, p.Limits.MaxObjectDuration)
	defer cancel()

	size, err := p.Objects.Size(ctx, obj.Bucket, obj.Key)
	if err != nil {
		log.Error("head object", "err", err)
		return Transient
	}
	if p.Limits.MaxObjectBytes > 0 && size > p.Limits.MaxObjectBytes {
		metrics.Poison.WithLabelValues("oversize_object").Inc()
		log.Error("object is over the size limit, not deleting",
			"bytes", size, "limit", p.Limits.MaxObjectBytes)
		return Transient
	}

	body, err := p.Objects.Get(ctx, obj.Bucket, obj.Key)
	if err != nil {
		log.Error("get object", "err", err)
		return Transient
	}
	defer body.Close()

	sink := p.NewSink() // fresh per object, so a previous object's batch cannot leak in
	var (
		good, bad, matched int
		ruleErrs           int
		fatal              error
	)

	err = decode.Records(ctx, body, p.Limits.MaxLineBytes,
		func(index int, event map[string]any) error {
			good++
			metrics.Events.Inc()

			// MatchView adds dot-joined aliases for nested fields, because
			// sigma-go's field lookup is a single flat map index and a rule
			// written userIdentity.type cannot otherwise see a nested object.
			// The event itself goes into the alert unchanged.
			ms, rerrs, err := p.Rules.Match(ctx, decode.MatchView(event))
			if err != nil {
				fatal = err
				return err
			}
			for _, re := range rerrs {
				ruleErrs++
				metrics.RuleErrors.WithLabelValues(re.RuleID).Inc()
				log.Error("rule failed on an event", "rule_id", re.RuleID,
					"file", re.File, "event_index", index, "err", re.Err)
			}

			for _, m := range ms {
				matched++
				if p.Limits.MaxAlertsPerObject > 0 && matched > p.Limits.MaxAlertsPerObject {
					// A rule broad enough to match most events turns one
					// object into hundreds of thousands of alerts on a queue
					// shared by every source. Failing at a known ceiling loses
					// this object's detections but keeps the shared queue --
					// and the log names the object and rule so it can be
					// replayed once the rule is fixed.
					fatal = fmt.Errorf("more than %d matches in one object (rule %s)",
						p.Limits.MaxAlertsPerObject, m.RuleID)
					return fatal
				}
				a, err := alert.New(alert.Input{
					Rule: m, LogSource: p.Source.Name,
					Bucket: obj.Bucket, Key: obj.Key, EventIndex: index,
					SQSMessageID: msg.MessageID, Event: event, Now: p.Now(),
				})
				if err != nil {
					fatal = err
					return err
				}
				if err := sink.Add(ctx, a); err != nil {
					// Add only errors when an internal flush failed, so some
					// alerts are durable and some are not. Not deleting
					// replays the object; the durable ones arrive again with
					// identical ids.
					fatal = err
					return err
				}
				metrics.Matches.WithLabelValues(m.RuleID, m.Level).Inc()
			}
			return nil
		},
		func(index int, derr error) error {
			bad++
			metrics.EventsUndecodable.Inc()
			log.Warn("undecodable record, skipping", "event_index", index, "err", derr)

			// One bad line does not condemn the object. Aborting here would
			// let a single truncated record in a two-hundred-thousand-line
			// Vector batch send the whole object to the DLQ and take every
			// good event with it -- the largest blast radius available for the
			// smallest fault. A flood is different: that is a format change,
			// and it must be loud rather than a slow drip of counters.
			if bad > minDecodeErrors && float64(bad)/float64(good+bad) > p.Limits.MaxDecodeErrorRate {
				fatal = fmt.Errorf("%d of %d records undecodable, over the %.2f%% limit",
					bad, good+bad, p.Limits.MaxDecodeErrorRate*100)
				return fatal
			}
			return nil
		},
	)
	if err != nil {
		if fatal != nil {
			metrics.Poison.WithLabelValues("decode_limit").Inc()
			log.Error("object aborted, not deleting", "err", fatal,
				"events", good, "undecodable", bad, "matched", matched)
			return Transient
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// Shutdown, or the per-object deadline. Either way nothing is
			// durable that should not be, and the message is handed back.
			log.Warn("object abandoned", "err", err, "events", good)
			return Transient
		}
		log.Error("reading object", "err", err, "events", good)
		return Transient
	}

	// This ordering is the reason the package exists. Flush is where alerts
	// become durable, and Run deletes only on Accepted. Deleting first, or
	// flushing after the delete, turns an ordinary SQS retry into permanent
	// loss of every detection in the object.
	if err := sink.Flush(ctx); err != nil {
		metrics.PublishErrors.WithLabelValues("flush").Inc()
		log.Error("flushing alerts, not deleting", "err", err, "matched", matched)
		return Transient
	}
	metrics.AlertsPublished.Add(float64(sink.Published()))

	metrics.ObjectsProcessed.Inc()
	metrics.ObjectBytes.Observe(float64(size))
	metrics.ObjectDuration.Observe(p.Now().Sub(start).Seconds())
	log.Info("object complete",
		"events", good, "undecodable", bad, "matched", matched,
		"published", sink.Published(), "rule_errors", ruleErrs,
		"bytes", size, "duration_ms", p.Now().Sub(start).Milliseconds())
	return Accepted
}
