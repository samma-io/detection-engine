package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/samma-io/detection-engine/internal/metrics"
)

// ErrVisibilityLost is the cancellation cause when a heartbeat fails.
var ErrVisibilityLost = errVisibilityLost{}

type errVisibilityLost struct{}

func (errVisibilityLost) Error() string { return "visibility extension failed" }

// RunConfig tunes one worker.
type RunConfig struct {
	WaitSeconds       int32
	VisibilityTimeout time.Duration
	HeartbeatInterval time.Duration
}

// Run drives one worker: long-poll, process, delete. It returns when ctx is
// cancelled.
//
// MaxNumberOfMessages is 1 deliberately. Receiving ten and processing them
// sequentially would save API calls, but only the in-flight message gets a
// visibility heartbeat -- the other nine would go visible again while the
// first large object was still being decoded, and be handed to another task.
// Vector's 300-second batch timeout means a handful of objects per source per
// five minutes, so the saving is noise against that risk.
func Run(ctx context.Context, q Queue, p *Processor, cfg RunConfig, log *slog.Logger) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		msgs, err := q.Receive(ctx, 1, cfg.WaitSeconds)
		if err != nil {
			if ctx.Err() != nil {
				return nil // cancellation, not a failure
			}
			log.Error("receive", "err", err)
			// A fixed short delay rather than exponential backoff: a receive
			// failure here is almost always throttling or a credential
			// refresh, and backing off to minutes would stall the source
			// quietly.
			if !sleep(ctx, time.Second) {
				return nil
			}
			continue
		}

		for _, msg := range msgs {
			p.handleOne(ctx, q, msg, cfg, log)
		}
	}
}

// handleOne owns one message's lifecycle: heartbeat, process, delete.
func (p *Processor) handleOne(ctx context.Context, q Queue, msg Message, cfg RunConfig, log *slog.Logger) {
	workCtx, cancel := context.WithCancelCause(ctx)
	hb := startHeartbeat(workCtx, cancel, heartbeatConfig{
		Queue:    q,
		Receipt:  msg.ReceiptHandle,
		Timeout:  cfg.VisibilityTimeout,
		Interval: cfg.HeartbeatInterval,
		Log:      log,
	})

	disp := p.Handle(workCtx, msg)

	// stop() blocks until the heartbeat goroutine has returned, so no
	// ChangeMessageVisibility can still be in flight when Delete runs.
	// Overlapping the two produces intermittent ReceiptHandleIsInvalid errors
	// that read like a bug for as long as it takes to work out they are not.
	hb.stop()
	cancel(nil)

	switch disp {
	case Accepted, Skipped:
		// A detached context: this delete must survive the SIGTERM that may
		// have just cancelled workCtx. Everything the message produced is
		// already durable, so failing to delete costs one duplicate replay --
		// but failing to even try guarantees one.
		delCtx, delCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		if err := q.Delete(delCtx, msg.ReceiptHandle); err != nil {
			metrics.DeleteErrors.Inc()
			log.Error("delete message", "msg_id", msg.MessageID, "err", err)
		}
		delCancel()

	case Transient:
		// Deliberately no delete. On shutdown, hand the message back at once
		// rather than making the next task wait out the remaining visibility
		// window.
		if ctx.Err() != nil {
			relCtx, relCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := q.ExtendVisibility(relCtx, msg.ReceiptHandle, 0); err != nil {
				log.Warn("releasing message on shutdown", "msg_id", msg.MessageID, "err", err)
			}
			relCancel()
		}
		log.Warn("transient failure, message not deleted",
			"msg_id", msg.MessageID, "receive_count", msg.ReceiveCount)
	}
}

// sleep waits, reporting false if the context ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
