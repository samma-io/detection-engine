package publisher_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/samma-io/detection-engine/internal/alert"
	"github.com/samma-io/detection-engine/internal/publisher"
	"github.com/samma-io/detection-engine/internal/rules"
)

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeSender records every batch and can be told to reject entries.
type fakeSender struct {
	batches [][]publisher.Outbound
	err     error

	// rejectRetryable and rejectPermanent name entry ids to fail, and are
	// consumed after the first call so a retry can succeed.
	rejectRetryable []string
	rejectPermanent []string
	oncePerCall     bool
}

func (f *fakeSender) SendBatch(_ context.Context, entries []publisher.Outbound) ([]publisher.Rejection, error) {
	cp := make([]publisher.Outbound, len(entries))
	copy(cp, entries)
	f.batches = append(f.batches, cp)
	if f.err != nil {
		return nil, f.err
	}

	var out []publisher.Rejection
	for _, id := range f.rejectRetryable {
		for _, e := range entries {
			if e.ID == id {
				out = append(out, publisher.Rejection{ID: id, Code: "ThrottlingException", SenderFault: false})
			}
		}
	}
	for _, id := range f.rejectPermanent {
		for _, e := range entries {
			if e.ID == id {
				out = append(out, publisher.Rejection{ID: id, Code: "InvalidMessageContents", SenderFault: true})
			}
		}
	}
	if f.oncePerCall {
		f.rejectRetryable = nil
	}
	return out, nil
}

func newBatcher(s publisher.Sender) *publisher.Batcher {
	return &publisher.Batcher{
		Sender: s,
		Log:    discard(),
		Sleep:  func(context.Context, time.Duration) error { return nil },
	}
}

func testAlert(t *testing.T, idx int, eventPad int) alert.Alert {
	t.Helper()
	ev := map[string]any{"eventName": "StopLogging"}
	if eventPad > 0 {
		ev["pad"] = strings.Repeat("x", eventPad)
	}
	a, err := alert.New(alert.Input{
		Rule:       rules.Match{RuleID: "rule-1", Title: "t", Level: "high", File: "f.yml"},
		LogSource:  "aws",
		Bucket:     "filtered-1-us-east-1",
		Key:        "aws/date=2026-09-02/o.ndjson.gz",
		EventIndex: idx,
		Event:      ev,
		Now:        time.Unix(0, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestFlush_EmptyIsANoop(t *testing.T) {
	s := &fakeSender{}
	b := newBatcher(s)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(s.batches) != 0 {
		t.Errorf("sent %d batches for nothing", len(s.batches))
	}
}

func TestPublish_SplitsAtTenEntries(t *testing.T) {
	// SQS rejects an eleventh entry outright, failing the whole request.
	s := &fakeSender{}
	b := newBatcher(s)
	for i := 0; i < 23; i++ {
		if err := b.Add(context.Background(), testAlert(t, i, 0)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(s.batches) != 3 {
		t.Fatalf("batches = %d, want 3", len(s.batches))
	}
	for i, want := range []int{10, 10, 3} {
		if got := len(s.batches[i]); got != want {
			t.Errorf("batch %d has %d entries, want %d", i, got, want)
		}
	}
	if b.Published() != 23 {
		t.Errorf("Published = %d, want 23", b.Published())
	}
}

func TestPublish_BatchStaysUnderTheRequestByteCapEvenWhenEachMessageIsLegal(t *testing.T) {
	// The trap: the 256 KiB limit is per REQUEST, not per message. Ten 100 KB
	// messages are each individually fine and collectively rejected.
	s := &fakeSender{}
	b := newBatcher(s)
	for i := 0; i < 6; i++ {
		if err := b.Add(context.Background(), testAlert(t, i, 100_000)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(s.batches) < 2 {
		t.Fatalf("batches = %d, want the byte cap to have split them", len(s.batches))
	}
	for i, batch := range s.batches {
		total := 0
		for _, e := range batch {
			total += len(e.Body)
		}
		if total > publisher.MaxRequestBytes {
			t.Errorf("batch %d is %d bytes, over the %d cap", i, total, publisher.MaxRequestBytes)
		}
		if len(batch) > publisher.MaxEntries {
			t.Errorf("batch %d has %d entries, over the %d cap", i, len(batch), publisher.MaxEntries)
		}
	}
}

func TestPublish_ReportsFailedEntriesRatherThanClaimingSuccess(t *testing.T) {
	// SendMessageBatch answers HTTP 200 with a Failed list. Ignoring it is a
	// silent alert loss, which is the one thing this service must not do.
	s := &fakeSender{rejectRetryable: []string{"1"}}
	b := newBatcher(s)
	b.MaxAttempts = 2
	if err := b.Add(context.Background(), testAlert(t, 0, 0)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	err := b.Flush(context.Background())
	if err == nil {
		t.Fatal("a persistently rejected entry must fail the flush")
	}
	if b.Published() != 0 {
		t.Errorf("Published = %d, want 0", b.Published())
	}
}

func TestPublish_RetriesThrottledEntriesAndSucceeds(t *testing.T) {
	s := &fakeSender{rejectRetryable: []string{"2"}, oncePerCall: true}
	b := newBatcher(s)
	for i := 0; i < 3; i++ {
		if err := b.Add(context.Background(), testAlert(t, i, 0)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(s.batches) != 2 {
		t.Fatalf("batches = %d, want a retry of just the rejected entry", len(s.batches))
	}
	if len(s.batches[1]) != 1 {
		t.Errorf("retry batch has %d entries, want only the rejected one", len(s.batches[1]))
	}
	if b.Published() != 3 {
		t.Errorf("Published = %d, want 3", b.Published())
	}
}

func TestPublish_PermanentlyRejectedEntryDoesNotFailTheOthers(t *testing.T) {
	// SenderFault means the message will never be accepted. Failing the whole
	// object over it would mean one malformed alert blocks every other alert
	// in the object forever, since the retry produces the same rejection.
	s := &fakeSender{rejectPermanent: []string{"1"}}
	var recorded []string
	b := newBatcher(s)
	b.OnPermanentReject = func(_ context.Context, out publisher.Outbound, _ publisher.Rejection) error {
		recorded = append(recorded, out.AlertID)
		return nil
	}
	for i := 0; i < 3; i++ {
		if err := b.Add(context.Background(), testAlert(t, i, 0)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush should survive a permanent rejection: %v", err)
	}
	if len(recorded) != 1 {
		t.Errorf("recorded %d rejections, want 1", len(recorded))
	}
	if b.Published() != 2 {
		t.Errorf("Published = %d, want the other 2", b.Published())
	}
}

func TestPublish_FailingToRecordAPermanentRejectionFailsTheFlush(t *testing.T) {
	// If we can neither send the alert nor record it, the object must be
	// replayed rather than acknowledged.
	s := &fakeSender{rejectPermanent: []string{"1"}}
	b := newBatcher(s)
	b.OnPermanentReject = func(context.Context, publisher.Outbound, publisher.Rejection) error {
		return errors.New("evidence store down")
	}
	if err := b.Add(context.Background(), testAlert(t, 0, 0)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Flush(context.Background()); err == nil {
		t.Fatal("losing both the alert and its evidence must fail the flush")
	}
}

func TestPublish_TransportErrorFailsTheFlush(t *testing.T) {
	s := &fakeSender{err: errors.New("connection reset")}
	b := newBatcher(s)
	if err := b.Add(context.Background(), testAlert(t, 0, 0)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Flush(context.Background()); err == nil {
		t.Fatal("a transport error must fail the flush")
	}
}

func TestPublish_OversizeAlertIsTruncatedNotDropped(t *testing.T) {
	s := &fakeSender{}
	var oversize int
	b := newBatcher(s)
	b.OnOversize = func(alert.Alert) { oversize++ }

	big := testAlert(t, 0, publisher.MaxMessageBytes+5_000)
	if err := b.Add(context.Background(), big); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if oversize != 1 {
		t.Errorf("oversize hook called %d times, want 1", oversize)
	}
	if len(s.batches) != 1 || len(s.batches[0]) != 1 {
		t.Fatalf("the alert was dropped instead of truncated: %v", s.batches)
	}

	var got alert.Alert
	if err := json.Unmarshal([]byte(s.batches[0][0].Body), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Truncated {
		t.Error("Truncated should be set so a consumer knows the event is missing")
	}
	if got.Event != nil {
		t.Error("the event body should be gone")
	}
	// The parts triage reads first must survive.
	if got.Rule.RuleID == "" || got.Provenance.Key == "" {
		t.Error("rule and provenance must survive truncation")
	}
	if got.EventSHA256 == "" {
		t.Error("the event digest should survive so the record is still identifiable")
	}
}

func TestPublish_TruncationDoesNotChangeTheAlertID(t *testing.T) {
	// A retry that truncates where the first attempt inlined must still
	// deduplicate to one alert.
	a := testAlert(t, 7, 0)
	if a.ID != a.Truncate().ID {
		t.Errorf("id changed on truncation: %q vs %q", a.ID, a.Truncate().ID)
	}
}

func TestAdd_FlushesWhenTheBatchFillsSoDurabilityIsMonotonic(t *testing.T) {
	s := &fakeSender{}
	b := newBatcher(s)
	for i := 0; i < 10; i++ {
		if err := b.Add(context.Background(), testAlert(t, i, 0)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	// The tenth Add should have flushed on its own.
	if len(s.batches) != 1 {
		t.Errorf("batches = %d, want the full batch to have auto-flushed", len(s.batches))
	}
	if b.Pending() != 0 {
		t.Errorf("Pending = %d, want 0", b.Pending())
	}
}
