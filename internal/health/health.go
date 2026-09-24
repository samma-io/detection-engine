// Package health serves the liveness and readiness endpoints.
package health

import (
	"net/http"
	"sync/atomic"
)

// Server tracks readiness. It owns no listener; Register attaches to a mux the
// caller owns, so the same mux can also serve /metrics.
type Server struct {
	ready atomic.Bool
}

// SetReady flips readiness. It is called after the ruleset loads, and again
// with false on shutdown.
func (s *Server) SetReady(ok bool) { s.ready.Store(ok) }

// Ready reports current readiness.
func (s *Server) Ready() bool { return s.ready.Load() }

// Register attaches the endpoints.
//
// /healthz is unconditionally 200: it answers "is this process alive", and
// tying it to readiness would make ECS kill a task that is merely still
// loading its rules.
//
// /readyz is gated. It goes true only once the ruleset has loaded, so a
// rules-bucket outage leaves the task not-ready and not consuming, which is
// the fail-closed behaviour we want. That in turn means the alarm has to be on
// task-start failures and readiness, not on queue depth -- queue depth also
// rises during an ordinary traffic spike.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
}
