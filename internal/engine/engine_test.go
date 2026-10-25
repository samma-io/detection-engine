package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/samma-io/detection-engine/internal/alert"
	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/rules"
	"github.com/samma-io/detection-engine/internal/source"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recorder is shared by the fakes so ordering between them is assertable.
// Two independent assertions cannot tell "flushed then deleted" from
// "deleted then flushed", which is the invariant that matters most here.
type recorder struct{ calls []string }

func (r *recorder) add(s string) { r.calls = append(r.calls, s) }

// ---------------------------------------------------------------- fakes

type fakeQueue struct {
	rec *recorder

	msgs      []Message
	deleted   []string
	deleteErr error

	visibilityCalls []int32
	visibilityErr   error
}

func (q *fakeQueue) Receive(ctx context.Context, _ int32, _ int32) ([]Message, error) {
	if len(q.msgs) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	out := q.msgs[:1]
	q.msgs = q.msgs[1:]
	return out, nil
}

func (q *fakeQueue) Delete(_ context.Context, receipt string) error {
	q.rec.add("delete")
	if q.deleteErr != nil {
		return q.deleteErr
	}
	q.deleted = append(q.deleted, receipt)
	return nil
}

func (q *fakeQueue) ExtendVisibility(_ context.Context, _ string, seconds int32) error {
	q.rec.add(fmt.Sprintf("visibility(%d)", seconds))
	q.visibilityCalls = append(q.visibilityCalls, seconds)
	return q.visibilityErr
}

type fakeObjects struct {
	body    []byte
	size    int64
	getErr  error
	headErr error
	gets    int
}

func (o *fakeObjects) Size(context.Context, string, string) (int64, error) {
	if o.headErr != nil {
		return 0, o.headErr
	}
	if o.size != 0 {
		return o.size, nil
	}
	return int64(len(o.body)), nil
}

func (o *fakeObjects) Get(context.Context, string, string) (io.ReadCloser, error) {
	o.gets++
	if o.getErr != nil {
		return nil, o.getErr
	}
	return io.NopCloser(bytes.NewReader(o.body)), nil
}

type fakeSink struct {
	rec       *recorder
	added     []alert.Alert
	flushErr  error
	addErr    error
	published int
}

func (s *fakeSink) Add(_ context.Context, a alert.Alert) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.added = append(s.added, a)
	return nil
}

func (s *fakeSink) Flush(context.Context) error {
	s.rec.add("flush")
	if s.flushErr != nil {
		return s.flushErr
	}
	s.published = len(s.added)
	return nil
}

func (s *fakeSink) Published() int { return s.published }

// ---------------------------------------------------------------- helpers

const matchingRule = `
title: CloudTrail Logging Disabled
id: 11111111-1111-1111-1111-111111111111
level: high
detection:
  sel:
    eventName: StopLogging
  condition: sel
`

const nestedRule = `
title: Assumed Role Stopped Logging
id: 22222222-2222-2222-2222-222222222222
level: high
detection:
  sel:
    eventName: StopLogging
    userIdentity.type: AssumedRole
  condition: sel
`

func ruleset(t *testing.T, bodies ...string) *rules.Set {
	t.Helper()
	files := make([]rules.File, 0, len(bodies))
	for i, b := range bodies {
		files = append(files, rules.File{Name: fmt.Sprintf("r%d.yml", i), Data: []byte(b)})
	}
	set, err := rules.Compile(files, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return set
}

func gzipNDJSON(t *testing.T, lines ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	for _, l := range lines {
		if _, err := w.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func notification(bucket, key string) string {
	return fmt.Sprintf(`{"Records":[{"eventName":"ObjectCreated:Put","s3":{
	  "bucket":{"name":%q},"object":{"key":%q,"size":1}}}]}`, bucket, key)
}

const testKey = "aws/date%3D2026-09-02/o.ndjson.gz"

type harness struct {
	proc *Processor
	q    *fakeQueue
	obj  *fakeObjects
	sink *fakeSink
	rec  *recorder
}

func newHarness(t *testing.T, set *rules.Set, body []byte) *harness {
	t.Helper()
	rec := &recorder{}
	obj := &fakeObjects{body: body}
	sink := &fakeSink{rec: rec}
	q := &fakeQueue{rec: rec}

	src, err := source.Lookup("aws")
	if err != nil {
		t.Fatal(err)
	}

	return &harness{
		rec: rec, q: q, obj: obj, sink: sink,
		proc: &Processor{
			Source:  src,
			Objects: obj,
			Rules:   set,
			NewSink: func() AlertSink { return sink },
			Limits: Limits{
				MaxObjectBytes:     1 << 30,
				MaxObjectDuration:  time.Minute,
				MaxDecodeErrorRate: 0.01,
				MaxAlertsPerObject: 10_000,
			},
			Now: func() time.Time { return time.Unix(0, 0) },
			Log: discard(),
		},
	}
}

func (h *harness) msg(body string) Message {
	return Message{MessageID: "m1", ReceiptHandle: "r1", Body: body, ReceiveCount: 1}
}

// runOne drives one message through the full lifecycle, so Delete is observed.
func (h *harness) runOne(t *testing.T, body string) {
	t.Helper()
	h.proc.handleOne(context.Background(), h.q, h.msg(body),
		RunConfig{VisibilityTimeout: 300 * time.Second, HeartbeatInterval: time.Hour},
		discard())
}

// ---------------------------------------------------------------- Tier 1

func TestHandle_PublishesAnAlertForAMatchingEvent(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule),
		gzipNDJSON(t, `{"eventName":"StopLogging"}`, `{"eventName":"GetObject"}`))

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Accepted {
		t.Fatalf("disposition = %v, want Accepted", got)
	}
	if len(h.sink.added) != 1 {
		t.Fatalf("alerts = %d, want 1", len(h.sink.added))
	}
	a := h.sink.added[0]
	if a.Rule.RuleID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("rule id = %q", a.Rule.RuleID)
	}
	// The key must be the decoded one, or the provenance cannot be used to
	// fetch the object again.
	if a.Provenance.Key != "aws/date=2026-09-02/o.ndjson.gz" {
		t.Errorf("key = %q, want the URL-decoded form", a.Provenance.Key)
	}
	if a.Provenance.EventIndex != 0 {
		t.Errorf("event_index = %d, want 0", a.Provenance.EventIndex)
	}
}

// TestRun_DeletesOnlyAfterFlushSucceeds is the ordering this service exists to
// protect. Deleting before the flush turns an ordinary SQS retry into
// permanent loss of every detection in the object.
func TestRun_DeletesOnlyAfterFlushSucceeds(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	h.runOne(t, notification("b", testKey))

	var seen []string
	for _, c := range h.rec.calls {
		if c == "flush" || c == "delete" {
			seen = append(seen, c)
		}
	}
	if len(seen) != 2 || seen[0] != "flush" || seen[1] != "delete" {
		t.Fatalf("call order = %v, want [flush delete]", seen)
	}
}

// TestRun_DoesNotDeleteWhenAlertPublishFails is the money invariant.
func TestRun_DoesNotDeleteWhenAlertPublishFails(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	h.sink.flushErr = errors.New("sqs unavailable")

	h.runOne(t, notification("b", testKey))

	if len(h.q.deleted) != 0 {
		t.Fatal("message was deleted even though its alerts were never published")
	}
}

func TestRun_DoesNotDeleteWhenAddFailsMidObject(t *testing.T) {
	// Add errors only when an internal flush failed, so some alerts are
	// durable and some are not: the object must be replayed.
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	h.sink.addErr = errors.New("internal flush failed")

	h.runOne(t, notification("b", testKey))

	if len(h.q.deleted) != 0 {
		t.Fatal("message deleted after a partial publish")
	}
}

func TestHandle_UndecodableBodyIsNotDeleted(t *testing.T) {
	// Deleting would lose the reference to an object still sitting in S3,
	// with nothing recording that it was never examined. Not deleting walks
	// it to the DLQ, which is where its body survives for fourteen days.
	h := newHarness(t, ruleset(t, matchingRule), nil)
	if got := h.proc.Handle(context.Background(), h.msg("{ not json")); got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
	h.runOne(t, "{ not json")
	if len(h.q.deleted) != 0 {
		t.Error("an undecodable body must not be deleted")
	}
}

func TestHandle_TestEventIsSkippedAndDeleted(t *testing.T) {
	// S3 sends one when a notification is configured. Treating it as
	// malformed would park it in the DLQ on the first deploy of every lane.
	h := newHarness(t, ruleset(t, matchingRule), nil)
	body := `{"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"b"}`

	if got := h.proc.Handle(context.Background(), h.msg(body)); got != Skipped {
		t.Fatalf("disposition = %v, want Skipped", got)
	}
	h.runOne(t, body)
	if len(h.q.deleted) != 1 {
		t.Error("a TestEvent should be deleted, not retried forever")
	}
}

func TestHandle_ObjectOutsideThisSourcesPrefixIsRefused(t *testing.T) {
	// The queue is subscribed to the wrong notification. Evaluating aws rules
	// against github events would produce confident nonsense.
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	got := h.proc.Handle(context.Background(), h.msg(notification("b", "github/date%3D2026-09-02/o.gz")))
	if got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
	if len(h.sink.added) != 0 {
		t.Error("no rule should have been evaluated against another source's object")
	}
}

// ---------------------------------------------------------------- decode policy

func TestHandle_OneBadRecordDoesNotAbandonTheObject(t *testing.T) {
	// Aborting would send a 200,000-line object to the DLQ over one truncated
	// record, taking every good event with it.
	h := newHarness(t, ruleset(t, matchingRule),
		gzipNDJSON(t, `{"eventName":"StopLogging"}`, `{ truncated`, `{"eventName":"StopLogging"}`))

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Accepted {
		t.Fatalf("disposition = %v, want Accepted", got)
	}
	if len(h.sink.added) != 2 {
		t.Errorf("alerts = %d, want 2 from the good records", len(h.sink.added))
	}
}

func TestHandle_AFloodOfBadRecordsFailsTheObject(t *testing.T) {
	// A systematic format change must be loud, not a slow drip of counters.
	lines := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		lines = append(lines, `{ truncated`)
	}
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, lines...))

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
}

func TestHandle_ASmallObjectOfEntirelyBadRecordsIsToleratedByTheGrace(t *testing.T) {
	// The ratio means nothing without a sample: a one-record object whose
	// single record is corrupt would otherwise be a 100% error rate.
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{ truncated`))
	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Accepted {
		t.Fatalf("disposition = %v, want Accepted", got)
	}
}

// ---------------------------------------------------------------- limits

func TestHandle_OversizeObjectIsRefusedBeforeBeingStreamed(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	h.obj.size = 1 << 40
	h.proc.Limits.MaxObjectBytes = 1 << 20

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
	if len(h.sink.added) != 0 {
		t.Error("an oversize object should not be read at all")
	}
}

func TestHandle_AlertCapAbortsTheObject(t *testing.T) {
	// A rule broad enough to match most events turns one object into hundreds
	// of thousands of alerts on a queue shared by every source.
	lines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		lines = append(lines, `{"eventName":"StopLogging"}`)
	}
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, lines...))
	h.proc.Limits.MaxAlertsPerObject = 5

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
}

func TestHandle_TransientS3ErrorIsNotDeleted(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), nil)
	h.obj.getErr = errors.New("503 slow down")
	h.runOne(t, notification("b", testKey))
	if len(h.q.deleted) != 0 {
		t.Error("a retryable S3 error must not delete the message")
	}
}

// ---------------------------------------------------------------- nested fields

// TestHandle_DottedRuleFieldsMatchThroughTheMatchView is the end-to-end guard
// for the sigma-go behaviour that would otherwise disable most upstream rules
// silently: field lookup is one flat map index, so userIdentity.type cannot
// see a nested object.
func TestHandle_DottedRuleFieldsMatchThroughTheMatchView(t *testing.T) {
	h := newHarness(t, ruleset(t, nestedRule),
		gzipNDJSON(t, `{"eventName":"StopLogging","userIdentity":{"type":"AssumedRole"}}`))

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Accepted {
		t.Fatalf("disposition = %v, want Accepted", got)
	}
	if len(h.sink.added) != 1 {
		t.Fatalf("alerts = %d, want 1 -- dotted Sigma fields are not matching", len(h.sink.added))
	}
	// And the alert must carry the event as the source emitted it, not the
	// flattened view.
	ev := h.sink.added[0].Event
	if _, leaked := ev["userIdentity.type"]; leaked {
		t.Error("the flattened alias leaked into the alert's event")
	}
	if _, ok := ev["userIdentity"].(map[string]any); !ok {
		t.Error("the alert's event lost its nested structure")
	}
}

// ---------------------------------------------------------------- shutdown

func TestHandle_CancelledContextMidObjectIsTransient(t *testing.T) {
	// ECS caps stopTimeout, so finishing a large object on SIGTERM is not an
	// option. Abandoning cleanly and letting SQS redeliver is.
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := h.proc.Handle(ctx, h.msg(notification("b", testKey))); got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
}

func TestHandleOne_ShutdownReleasesTheMessageImmediately(t *testing.T) {
	// Otherwise the next task waits out the remaining visibility window
	// before it can retry.
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	h.sink.flushErr = errors.New("sqs unavailable")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.proc.handleOne(ctx, h.q, h.msg(notification("b", testKey)),
		RunConfig{VisibilityTimeout: 300 * time.Second, HeartbeatInterval: time.Hour}, discard())

	if len(h.q.deleted) != 0 {
		t.Error("message deleted on shutdown despite a failed publish")
	}
	var released bool
	for _, c := range h.q.visibilityCalls {
		if c == 0 {
			released = true
		}
	}
	if !released {
		t.Error("expected ChangeMessageVisibility(0) to hand the message back")
	}
}

func TestHandleOne_DeleteSurvivesACancelledParentContext(t *testing.T) {
	// The delete runs on a detached context. Without that, a SIGTERM arriving
	// between the flush and the delete would republish every alert in the
	// object on the next delivery.
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"GetObject"}`))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.proc.handleOne(ctx, h.q, h.msg(`{"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"b"}`),
		RunConfig{VisibilityTimeout: 300 * time.Second, HeartbeatInterval: time.Hour}, discard())

	if len(h.q.deleted) != 1 {
		t.Error("delete should have used a detached context and succeeded")
	}
}

// ---------------------------------------------------------------- heartbeat

func TestHeartbeat_ExtendsVisibilityWhileWorkIsInFlight(t *testing.T) {
	rec := &recorder{}
	q := &fakeQueue{rec: rec}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	hb := startHeartbeat(ctx, cancel, heartbeatConfig{
		Queue: q, Receipt: "r1",
		Timeout: 300 * time.Second, Interval: 5 * time.Millisecond,
		Log: discard(),
	})
	time.Sleep(40 * time.Millisecond)
	hb.stop()

	if len(q.visibilityCalls) == 0 {
		t.Fatal("no visibility extension was issued")
	}
	if q.visibilityCalls[0] != 300 {
		t.Errorf("extended by %d, want the full 300s timeout", q.visibilityCalls[0])
	}
}

func TestHeartbeat_FailureCancelsTheWorkWithACause(t *testing.T) {
	// A failed extension means the message is visible to another task.
	// Continuing would have two tasks publishing the same alerts.
	rec := &recorder{}
	q := &fakeQueue{rec: rec, visibilityErr: errors.New("ReceiptHandleIsInvalid")}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	startHeartbeat(ctx, cancel, heartbeatConfig{
		Queue: q, Receipt: "r1",
		Timeout: 300 * time.Second, Interval: time.Millisecond,
		Log: discard(),
	})

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a failed extension did not cancel the work")
	}
	if !errors.Is(context.Cause(ctx), ErrVisibilityLost) {
		t.Errorf("cause = %v, want ErrVisibilityLost", context.Cause(ctx))
	}
}

func TestHeartbeat_StopBlocksUntilTheGoroutineHasExited(t *testing.T) {
	// Otherwise a ChangeMessageVisibility can still be in flight when Delete
	// runs, producing intermittent ReceiptHandleIsInvalid errors that read
	// like a bug.
	rec := &recorder{}
	q := &fakeQueue{rec: rec}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	hb := startHeartbeat(ctx, cancel, heartbeatConfig{
		Queue: q, Receipt: "r1",
		Timeout: 300 * time.Second, Interval: time.Millisecond,
		Log: discard(),
	})
	hb.stop()

	before := len(q.visibilityCalls)
	time.Sleep(20 * time.Millisecond)
	if len(q.visibilityCalls) != before {
		t.Error("the heartbeat kept running after stop() returned")
	}
}

// ---------------------------------------------------------------- Run

func TestRun_ReturnsCleanlyOnCancellation(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), gzipNDJSON(t, `{"eventName":"StopLogging"}`))
	h.q.msgs = []Message{h.msg(notification("b", testKey))}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := Run(ctx, h.q, h.proc, RunConfig{
		WaitSeconds: 0, VisibilityTimeout: 300 * time.Second, HeartbeatInterval: time.Hour,
	}, discard()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(h.q.deleted) != 1 {
		t.Errorf("deleted %d messages, want 1", len(h.q.deleted))
	}
}

func TestDisposition_StringIsStableForMetricLabels(t *testing.T) {
	for d, want := range map[Disposition]string{
		Accepted: "accepted", Skipped: "skipped", Transient: "transient",
	} {
		if got := d.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", d, got, want)
		}
	}
}

var _ = strings.TrimSpace

// ---------------------------------------------------------------- alarm log contract

// jsonLog captures what the process logger would write: logging.New is a JSON
// handler, and the aws-siem metric filters match on its level and msg keys.
func jsonLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
}

// onlyLineWith returns the single JSON log line whose msg is want.
func onlyLineWith(t *testing.T, buf *bytes.Buffer, want string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		if rec["msg"] == want {
			found = append(found, rec)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one log line with msg %q, got %d in:\n%s", want, len(found), buf)
	}
	return found[0]
}

func TestAlarmMessages_AreTheStringsTheMetricFiltersMatch(t *testing.T) {
	// Duplicated from aws-siem's alarms module on purpose: changing either
	// side alone disables an alarm without failing anything.
	if MsgRuleEvaluationFailed != "rule evaluation failed" {
		t.Errorf("MsgRuleEvaluationFailed = %q", MsgRuleEvaluationFailed)
	}
	if MsgPanicRecovered != "panic recovered" {
		t.Errorf("MsgPanicRecovered = %q", MsgPanicRecovered)
	}
}

func TestLogRuleError_IsAnErrorLineWithTheStableMsg(t *testing.T) {
	log, buf := jsonLog()
	logRuleError(log, rules.RuleError{
		RuleID: "11111111-1111-1111-1111-111111111111", File: "r0.yml",
		Err: errors.New("panic during evaluation: boom"),
	}, 7)

	rec := onlyLineWith(t, buf, MsgRuleEvaluationFailed)
	if rec["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", rec["level"])
	}
	if rec["rule_id"] != "11111111-1111-1111-1111-111111111111" || rec["file"] != "r0.yml" {
		t.Errorf("the line must name the rule: %v", rec)
	}
	if rec["event_index"] != float64(7) {
		t.Errorf("event_index = %v, want 7", rec["event_index"])
	}
}

// panickingObjects stands in for any bug below Handle that panics.
type panickingObjects struct{ *fakeObjects }

func (panickingObjects) Size(context.Context, string, string) (int64, error) {
	panic("boom")
}

func TestHandle_RecoveredPanicIsAnErrorLineWithTheStableMsg(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), nil)
	log, buf := jsonLog()
	h.proc.Log = log
	h.proc.Objects = panickingObjects{h.obj}

	if got := h.proc.Handle(context.Background(), h.msg(notification("b", testKey))); got != Transient {
		t.Errorf("disposition = %v, want Transient", got)
	}
	rec := onlyLineWith(t, buf, MsgPanicRecovered)
	if rec["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", rec["level"])
	}
	if rec["panic"] != "boom" || rec["msg_id"] != "m1" {
		t.Errorf("the line must carry the panic and the message id: %v", rec)
	}
}

func inlineMsg(body []byte) Message {
	return Message{MessageID: "samma.logs.aws/7", ReceiptHandle: "7", ReceiveCount: 1,
		Inline: &Inline{Ref: decode.ObjectRef{Bucket: "nats:SIEM_LOGS", Key: "samma.logs.aws/7"}, Body: body}}
}

func TestHandle_InlineRecordsAreEvaluatedWithStreamProvenance(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), nil)

	// Plain NDJSON, not gzipped: the decoder sniffs either.
	body := []byte("{\"eventName\":\"StopLogging\"}\n{\"eventName\":\"GetObject\"}\n")
	if got := h.proc.Handle(context.Background(), inlineMsg(body)); got != Accepted {
		t.Fatalf("disposition = %v, want Accepted", got)
	}
	if len(h.sink.added) != 1 {
		t.Fatalf("alerts = %d, want 1", len(h.sink.added))
	}
	if p := h.sink.added[0].Provenance; p.Bucket != "nats:SIEM_LOGS" || p.Key != "samma.logs.aws/7" {
		t.Errorf("provenance = %s/%s", p.Bucket, p.Key)
	}
	if h.obj.gets != 0 {
		t.Errorf("an inline message must not touch the object store")
	}
}

func TestHandle_OversizeInlineMessageIsTransient(t *testing.T) {
	h := newHarness(t, ruleset(t, matchingRule), nil)
	h.proc.Limits.MaxObjectBytes = 4
	if got := h.proc.Handle(context.Background(), inlineMsg([]byte(`{"eventName":"StopLogging"}`))); got != Transient {
		t.Fatalf("disposition = %v, want Transient", got)
	}
}
