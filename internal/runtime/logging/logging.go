// Package logging builds the process logger.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// New returns a JSON logger. CloudWatch indexes JSON log fields, and the ECS
// task definition sets the awslogs driver, so structured output is queryable
// in Logs Insights without a parser.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// ParseLevel reads a configured log level, defaulting to info for anything it
// does not recognise. A typo should reduce detail, never silence the engine.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
