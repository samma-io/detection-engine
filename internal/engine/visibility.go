package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/samma-io/detection-engine/internal/metrics"
)

type heartbeatConfig struct {
	Queue    Queue
	Receipt  string
	Timeout  time.Duration
	Interval time.Duration
	Log      *slog.Logger
}

type heartbeat struct {
	done chan struct{}
	quit chan struct{}
}

// startHeartbeat keeps one message invisible for as long as it is being
// processed, and cancels the work if it stops being able to.
//
// ChangeMessageVisibility sets the timeout relative to now rather than to the
// original receive, so repeated calls slide the window instead of
// accumulating. Interval should be a fraction of Timeout so that one lost
// extension still leaves room to recover.
//
// Cancelling on failure is the half that matters. A failed extension means the
// message is visible, or about to be, to another task. Continuing would have
// two tasks streaming the same object and publishing the same alerts.
// Deterministic alert ids make that survivable downstream; they do not make it
// correct, and the duplicated work is real.
func startHeartbeat(ctx context.Context, cancel context.CancelCauseFunc, cfg heartbeatConfig) *heartbeat {
	h := &heartbeat{done: make(chan struct{}), quit: make(chan struct{})}

	go func() {
		defer close(h.done)
		t := time.NewTicker(cfg.Interval)
		defer t.Stop()

		for {
			select {
			case <-h.quit:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				// Detached, so a cancellation racing the tick does not turn
				// into a spurious extension failure.
				extCtx, c := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				err := cfg.Queue.ExtendVisibility(extCtx, cfg.Receipt, int32(cfg.Timeout.Seconds()))
				c()
				if err != nil {
					metrics.VisibilityErrors.Inc()
					cfg.Log.Error("visibility extension failed, abandoning message", "err", err)
					cancel(ErrVisibilityLost)
					return
				}
				metrics.VisibilityExtensions.Inc()
			}
		}
	}()

	return h
}

// stop blocks until the goroutine has returned, so the caller can rely on no
// further ChangeMessageVisibility being issued.
func (h *heartbeat) stop() {
	close(h.quit)
	<-h.done
}
