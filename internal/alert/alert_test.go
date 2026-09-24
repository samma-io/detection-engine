package alert_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/samma-io/detection-engine/internal/alert"
	"github.com/samma-io/detection-engine/internal/rules"
)

func input() alert.Input {
	return alert.Input{
		Rule:         rules.Match{RuleID: "11111111-1111", Title: "CloudTrail Logging Disabled", Level: "high", File: "ct.yml"},
		LogSource:    "aws",
		Bucket:       "filtered-logs",
		Key:          "aws/date=2026-09-02/1756813200-6f2a91cc.ndjson.gz",
		EventIndex:   48213,
		SQSMessageID: "b7c1e0f2-first-delivery",
		Event:        map[string]any{"eventName": "StopLogging"},
		Now:          time.Date(2026, 9, 2, 11, 47, 3, 0, time.UTC),
	}
}

func TestNew_IsStableAcrossRedelivery(t *testing.T) {
	// Every path into this service is at-least-once: SQS redelivers, S3
	// raises duplicate notifications, and a SIGTERM mid-object replays it from
	// the start. All three must produce the same id or each becomes a
	// duplicate ticket.
	first, err := alert.New(input())
	if err != nil {
		t.Fatal(err)
	}

	redelivery := input()
	redelivery.Now = redelivery.Now.Add(3 * time.Hour) // a later clock
	redelivery.SQSMessageID = "a-different-delivery"   // a different delivery
	second, err := alert.New(redelivery)
	if err != nil {
		t.Fatal(err)
	}

	if first.ID != second.ID {
		t.Errorf("id changed on redelivery:\n  %s\n  %s", first.ID, second.ID)
	}
}

func TestNew_DifferentEventIndexGivesADifferentID(t *testing.T) {
	// Two identical failed logins in one object are two findings.
	a, _ := alert.New(input())
	in := input()
	in.EventIndex++
	b, _ := alert.New(in)
	if a.ID == b.ID {
		t.Error("two records in the same object collapsed to one alert id")
	}
}

func TestNew_DifferentRuleGivesADifferentID(t *testing.T) {
	a, _ := alert.New(input())
	in := input()
	in.Rule.RuleID = "22222222-2222"
	b, _ := alert.New(in)
	if a.ID == b.ID {
		t.Error("two rules firing on one event collapsed to one alert id")
	}
}

func TestID_SeparatorPreventsFieldBoundaryCollisions(t *testing.T) {
	// Without a separator, ("ab","c") and ("a","bc") hash identically, and
	// rule ids and S3 keys are exactly the kind of adjacent free-text fields
	// where that collides.
	x := alert.ID("ab", "c", "bucket", "key", 0)
	y := alert.ID("a", "bc", "bucket", "key", 0)
	if x == y {
		t.Error("adjacent fields are concatenated without a separator")
	}
}

func TestNew_EventDigestIsRecordedForGrouping(t *testing.T) {
	a, err := alert.New(input())
	if err != nil {
		t.Fatal(err)
	}
	if a.EventSHA256 == "" {
		t.Error("EventSHA256 should be set")
	}
	if a.EventBytes == 0 {
		t.Error("EventBytes should be set")
	}
}

func TestEncode_ProducesTheDocumentedEnvelope(t *testing.T) {
	a, err := alert.New(input())
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"schema_version", "id", "alerted_at", "log_source", "rule", "provenance", "event",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("envelope is missing %q", key)
		}
	}
	if got["schema_version"] != alert.SchemaVersion {
		t.Errorf("schema_version = %v", got["schema_version"])
	}
	// Vector stamps a "source" field inside every event, so the envelope must
	// not also have a top-level "source" with a different meaning.
	if _, clash := got["source"]; clash {
		t.Error("envelope has a top-level \"source\", which collides with Vector's event field")
	}
}

func TestEncode_InvalidUTF8InTheEventIsSanitisedNotRejected(t *testing.T) {
	// SQS rejects invalid UTF-8 with InvalidMessageContents, and it rejects
	// the whole request -- so one bad byte in a user agent would take out
	// every alert batched with it. Marshalling from the decoded map coerces
	// invalid bytes to U+FFFD, which is why the alert never carries the
	// original line through.
	in := input()
	in.Event = map[string]any{"userAgent": string([]byte{0x41, 0xff, 0xfe, 0x42})}
	a, err := alert.New(in)
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !json.Valid(body) {
		t.Fatal("encoded alert is not valid JSON")
	}
	for i, r := range string(body) {
		if r == 0xfffd {
			continue
		}
		if r > 0x10ffff {
			t.Fatalf("invalid rune survived at %d", i)
		}
	}
}

func TestTruncate_KeepsEverythingThatIdentifiesTheAlert(t *testing.T) {
	a, _ := alert.New(input())
	tr := a.Truncate()

	if tr.Event != nil {
		t.Error("event should be dropped")
	}
	if !tr.Truncated {
		t.Error("Truncated should be set")
	}
	if tr.ID != a.ID {
		t.Error("id must not change")
	}
	if tr.Rule.RuleID != a.Rule.RuleID || tr.Provenance.Key != a.Provenance.Key {
		t.Error("rule and provenance must survive")
	}
	if tr.EventSHA256 != a.EventSHA256 {
		t.Error("the event digest must survive so the record stays identifiable")
	}
}
