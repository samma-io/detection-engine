// Package publisher batches alerts onto the shared detections queue.
package publisher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/samma-io/detection-engine/internal/alert"
)

// SQS limits, with the margins we actually send at.
const (
	// MaxEntries is SQS's hard limit. An eleventh entry rejects the whole
	// request.
	MaxEntries = 10

	// MaxRequestBytes caps one SendMessageBatch request.
	//
	// The 256 KiB limit applies to the whole request, not to each message:
	// ten 100 KB messages are each individually legal and collectively
	// rejected. The margin leaves room for entry ids and XML framing.
	MaxRequestBytes = 250_000

	// MaxMessageBytes caps one message, leaving the same kind of margin.
	MaxMessageBytes = 240_000

	// DefaultMaxAttempts bounds retries of retryable rejections.
	DefaultMaxAttempts = 4
)

// Outbound is one message on its way to the queue.
type Outbound struct {
	// ID is the batch-local entry id, which SQS uses to correlate the Failed
	// list back to the entries. It is not the alert id.
	ID   string
	Body string

	// AlertID is carried for logging and evidence only.
	AlertID string
}

// Rejection is one entry SQS refused.
type Rejection struct {
	ID      string
	Code    string
	Message string

	// SenderFault distinguishes our problem from theirs. True means the
	// message itself is unacceptable and will never succeed; false means
	// throttling or a server error and is worth retrying.
	SenderFault bool
}

// Sender is the slice of SQS this package needs. It returns the per-entry
// rejections rather than an error, because SendMessageBatch answers HTTP 200
// with a Failed list and treating that as success drops alerts silently.
type Sender interface {
	SendBatch(ctx context.Context, entries []Outbound) ([]Rejection, error)
}

// Batcher accumulates alerts and makes them durable.
//
// It is not safe for concurrent use, and that is a design statement rather
// than an omission. One worker goroutine owns one Batcher for the duration of
// one object, so there is no second writer to race with. A mutex would
// advertise that a Batcher may be shared, and sharing one breaks the
// invariant the whole service rests on: Flush is what makes alerts durable,
// and it has to correspond to exactly one message's delete. Alerts from
// message A sitting in a batch that message B flushes would let B's delete
// make A deletable while A's alerts were still buffered.
type Batcher struct {
	Sender Sender
	Log    *slog.Logger

	// MaxAttempts bounds retries of retryable rejections. Zero means
	// DefaultMaxAttempts.
	MaxAttempts int

	// Sleep is injected so tests do not wait. Zero means time.Sleep.
	Sleep func(context.Context, time.Duration) error

	// OnOversize is called when an alert's event had to be dropped.
	OnOversize func(a alert.Alert)

	// OnPermanentReject is called for an entry SQS will never accept. It is
	// the last chance to record the alert somewhere; returning an error fails
	// the flush.
	OnPermanentReject func(ctx context.Context, out Outbound, r Rejection) error

	pending      []Outbound
	pendingBytes int
	published    int
	nextID       int
}

// Add queues one alert, flushing when the batch is full.
//
// An error means some alerts for this object are durable and some are not, so
// the caller must not delete its queue message.
func (b *Batcher) Add(ctx context.Context, a alert.Alert) error {
	body, err := a.Encode()
	if err != nil {
		return fmt.Errorf("encoding alert %s: %w", a.ID, err)
	}

	if len(body) > MaxMessageBytes {
		// Drop the event body rather than the alert. The rule metadata and
		// the provenance are what triage reads first, and the provenance
		// names the object and record index so the original is recoverable.
		truncated := a.Truncate()
		tbody, terr := truncated.Encode()
		if terr != nil {
			return fmt.Errorf("encoding truncated alert %s: %w", a.ID, terr)
		}
		if len(tbody) > MaxMessageBytes {
			// The envelope alone is too big, which means a rule with an
			// enormous description or tag list. Nothing sensible left to trim.
			return fmt.Errorf("alert %s is %d bytes even without its event, over the %d limit",
				a.ID, len(tbody), MaxMessageBytes)
		}
		if b.OnOversize != nil {
			b.OnOversize(a)
		}
		b.Log.Warn("alert event dropped, over the SQS message limit",
			"alert_id", a.ID, "rule_id", a.Rule.RuleID, "event_bytes", a.EventBytes,
			"key", a.Provenance.Key, "event_index", a.Provenance.EventIndex)
		body = tbody
	}

	// Flush before adding when this message would take the request over its
	// byte cap, so the cap is respected rather than merely observed.
	if len(b.pending) > 0 && b.pendingBytes+len(body) > MaxRequestBytes {
		if err := b.Flush(ctx); err != nil {
			return err
		}
	}

	b.nextID++
	b.pending = append(b.pending, Outbound{
		ID:      strconv.Itoa(b.nextID),
		Body:    string(body),
		AlertID: a.ID,
	})
	b.pendingBytes += len(body)

	if len(b.pending) >= MaxEntries {
		return b.Flush(ctx)
	}
	return nil
}

// Flush sends every pending alert.
//
// Nothing added is durable until a Flush returns nil. Retryable rejections are
// retried in place; permanently rejected entries are handed to
// OnPermanentReject and dropped from the batch so that one malformed alert
// does not take the other nine down with it.
func (b *Batcher) Flush(ctx context.Context) error {
	if len(b.pending) == 0 {
		return nil
	}

	batch := b.pending
	// Cleared up front so a failed flush cannot double-send on a later call;
	// the caller's contract on error is to replay the whole object.
	b.pending = nil
	b.pendingBytes = 0

	attempts := b.MaxAttempts
	if attempts <= 0 {
		attempts = DefaultMaxAttempts
	}

	byID := make(map[string]Outbound, len(batch))
	for _, o := range batch {
		byID[o.ID] = o
	}

	for attempt := 1; ; attempt++ {
		rejections, err := b.Sender.SendBatch(ctx, batch)
		if err != nil {
			return fmt.Errorf("send batch (attempt %d): %w", attempt, err)
		}

		var retry []Outbound
		var permanent []Rejection
		for _, r := range rejections {
			if r.SenderFault {
				permanent = append(permanent, r)
				continue
			}
			if o, ok := byID[r.ID]; ok {
				retry = append(retry, o)
			}
		}

		b.published += len(batch) - len(retry) - len(permanent)

		for _, r := range permanent {
			out := byID[r.ID]
			b.Log.Error("alert permanently rejected by SQS",
				"alert_id", out.AlertID, "code", r.Code, "message", r.Message)
			if b.OnPermanentReject != nil {
				if err := b.OnPermanentReject(ctx, out, r); err != nil {
					return fmt.Errorf("recording rejected alert %s: %w", out.AlertID, err)
				}
			}
		}

		if len(retry) == 0 {
			return nil
		}
		if attempt >= attempts {
			return fmt.Errorf("%d alerts still rejected after %d attempts", len(retry), attempt)
		}

		if err := b.sleep(ctx, backoff(attempt)); err != nil {
			return err
		}
		batch = retry
	}
}

// Published is the number of alerts confirmed durable.
func (b *Batcher) Published() int { return b.published }

// Pending is the number of alerts not yet sent, for assertions.
func (b *Batcher) Pending() int { return len(b.pending) }

func (b *Batcher) sleep(ctx context.Context, d time.Duration) error {
	if b.Sleep != nil {
		return b.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// backoff is exponential with a low ceiling. Retryable rejections here are
// throttling, and the visibility heartbeat is holding the message, so there is
// no benefit to waiting long.
func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * 200 * time.Millisecond
	if d > 3*time.Second {
		return 3 * time.Second
	}
	return d
}

// ErrNoSender guards a misconfigured Batcher.
var ErrNoSender = errors.New("publisher: no sender configured")
