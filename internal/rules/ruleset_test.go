package rules_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/rules"
)

func file(name, body string) rules.File {
	return rules.File{Name: name, Data: []byte(body)}
}

const stopLogging = `
title: CloudTrail Logging Disabled
id: 11111111-1111-1111-1111-111111111111
level: high
tags: [attack.defense_evasion]
detection:
  sel:
    eventSource: cloudtrail.amazonaws.com
    eventName: StopLogging
  condition: sel
`

func TestCompile_ZeroRulesIsAStartupError(t *testing.T) {
	// The single worst failure this service has. An engine with no rules
	// starts, drains its queue, matches nothing, deletes every message, and
	// makes queue depth go DOWN. No dashboard distinguishes it from a quiet
	// week.
	_, err := rules.Compile(nil, nil)
	if !errors.Is(err, rules.ErrNoRules) {
		t.Fatalf("err = %v, want ErrNoRules", err)
	}
}

func TestCompile_AggregationRuleIsRejectedLoudly(t *testing.T) {
	// Verified against sigma-go v0.6.6: evaluating an aggregation rule calls
	// rule.count, which is nil, and panics with a nil pointer dereference.
	// Rejecting at load time turns a crash loop into a failed deploy.
	_, err := rules.Compile([]rules.File{file("agg.yml", `
title: agg
id: 22222222-2222-2222-2222-222222222222
detection:
  sel:
    eventName: ConsoleLogin
  condition: sel | count() > 5
`)}, nil)
	if err == nil {
		t.Fatal("an aggregation rule must not compile")
	}
	if !strings.Contains(err.Error(), "agg.yml") {
		t.Errorf("error should name the file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "aggregation") {
		t.Errorf("error should say why, got: %v", err)
	}
}

func TestCompile_TimeframeRuleIsRejected(t *testing.T) {
	_, err := rules.Compile([]rules.File{file("tf.yml", `
title: tf
id: 33333333-3333-3333-3333-333333333333
detection:
  sel:
    eventName: ConsoleLogin
  condition: sel
  timeframe: 15m
`)}, nil)
	if err == nil {
		t.Fatal("a timeframe implies cross-event state and must not compile")
	}
}

func TestCompile_KeywordSearchIsRejected(t *testing.T) {
	// sigma-go returns "keywords unsupported" per event, which reads as a
	// noisy rule rather than a rule that cannot work.
	_, err := rules.Compile([]rules.File{file("kw.yml", `
title: kw
id: 44444444-4444-4444-4444-44444444444a
detection:
  keywords:
    - "password"
  condition: keywords
`)}, nil)
	if err == nil {
		t.Fatal("a keywords search must not compile")
	}
}

func TestCompile_UnknownModifierIsRejectedAtLoadTime(t *testing.T) {
	// Otherwise it is one rule error per event, forever.
	_, err := rules.Compile([]rules.File{file("mod.yml", `
title: mod
id: 55555555-5555-5555-5555-55555555555a
detection:
  sel:
    fieldName|notarealmodifier: x
  condition: sel
`)}, nil)
	if err == nil {
		t.Fatal("an unimplemented modifier must not compile")
	}
}

func TestCompile_RuleWithNoConditionIsRejected(t *testing.T) {
	// Parses, registers, matches nothing, ever.
	_, err := rules.Compile([]rules.File{file("empty.yml", `
title: empty
id: 66666666-6666-6666-6666-66666666666a
detection: {}
`)}, nil)
	if err == nil {
		t.Fatal("a rule with no condition must not compile")
	}
}

func TestCompile_EveryFailureIsReportedTogether(t *testing.T) {
	_, err := rules.Compile([]rules.File{
		file("a.yml", "not: valid: yaml: at: all:"),
		file("b.yml", `
title: b
id: 77777777-7777-7777-7777-77777777777a
detection:
  sel: {eventName: X}
  condition: sel | count() > 1
`),
	}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"a.yml", "b.yml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s, got:\n%v", want, err)
		}
	}
}

func TestCompile_OneBadRuleFailsTheWholeLoad(t *testing.T) {
	// Starting with the survivors would leave a detection silently missing
	// with no reason for anyone to look.
	_, err := rules.Compile([]rules.File{
		file("good.yml", stopLogging),
		file("bad.yml", "title: bad\nid: x\ndetection:\n  sel: {a: b}\n  condition: sel | count() > 1\n"),
	}, nil)
	if err == nil {
		t.Fatal("a partial ruleset must not load")
	}
}

func TestCompile_DuplicateRuleIDsAreRejected(t *testing.T) {
	// The alert id is derived from the rule id, so duplicates would make one
	// detection look like a redelivery of another.
	_, err := rules.Compile([]rules.File{
		file("one.yml", stopLogging),
		file("two.yml", stopLogging),
	}, nil)
	if err == nil {
		t.Fatal("duplicate rule ids must be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should say duplicate, got: %v", err)
	}
}

func TestCompile_MetadataIsCarriedOntoTheMatch(t *testing.T) {
	set, err := rules.Compile([]rules.File{file("ct.yml", stopLogging)}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	all := set.All()
	if len(all) != 1 {
		t.Fatalf("rules = %d, want 1", len(all))
	}
	m := all[0]
	if m.RuleID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("RuleID = %q", m.RuleID)
	}
	if m.Level != "high" {
		t.Errorf("Level = %q, want high (lowercased)", m.Level)
	}
	if m.File != "ct.yml" {
		t.Errorf("File = %q", m.File)
	}
	if len(m.Tags) != 1 || m.Tags[0] != "attack.defense_evasion" {
		t.Errorf("Tags = %v", m.Tags)
	}
}

// ---------------------------------------------------------------- matching

func TestMatch_FiresOnAMatchingEvent(t *testing.T) {
	set, err := rules.Compile([]rules.File{file("ct.yml", stopLogging)}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	event := map[string]any{
		"eventSource": "cloudtrail.amazonaws.com",
		"eventName":   "StopLogging",
	}
	matches, ruleErrs, err := set.Match(context.Background(), event)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(ruleErrs) != 0 {
		t.Fatalf("rule errors: %v", ruleErrs)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
}

func TestMatch_DoesNotFireOnANonMatchingEvent(t *testing.T) {
	set, _ := rules.Compile([]rules.File{file("ct.yml", stopLogging)}, nil)
	matches, _, err := set.Match(context.Background(), map[string]any{
		"eventSource": "s3.amazonaws.com",
		"eventName":   "GetObject",
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("matches = %d, want 0", len(matches))
	}
}

// TestMatch_DottedRuleFieldNeedsTheFlattenedView is the canary for the single
// most dangerous sigma-go behaviour this engine works around.
//
// sigma-go's field lookup is one flat map index, so a rule written
// userIdentity.type cannot see a nested object. Almost every upstream SigmaHQ
// rule for CloudTrail, GCP and Workspace uses dotted paths, so if this ever
// starts passing without decode.MatchView, hundreds of rules would be loading
// and silently never firing.
func TestMatch_DottedRuleFieldNeedsTheFlattenedView(t *testing.T) {
	const rule = `
title: assumed role stopped logging
id: 88888888-8888-8888-8888-88888888888a
level: high
detection:
  sel:
    eventName: StopLogging
    userIdentity.type: AssumedRole
  condition: sel
`
	set, err := rules.Compile([]rules.File{file("nested.yml", rule)}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	event := map[string]any{
		"eventName":    "StopLogging",
		"userIdentity": map[string]any{"type": "AssumedRole"},
	}

	raw, _, err := set.Match(context.Background(), event)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(raw) != 0 {
		t.Error("sigma-go now walks nested maps by itself -- re-check whether " +
			"decode.MatchView is still needed, and whether it now double-matches")
	}

	view, _, err := set.Match(context.Background(), decode.MatchView(event))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(view) != 1 {
		t.Fatalf("matches through MatchView = %d, want 1 -- dotted Sigma fields "+
			"are broken, which silently disables most upstream rules", len(view))
	}
}

// TestMatch_LargeIntegerFieldMatchesAfterNormalisation is the canary for the
// number-type workaround. GitHub audit records carry created_at as epoch
// millis; as a float64 it stringifies to scientific notation and misses.
func TestMatch_LargeIntegerFieldMatchesAfterNormalisation(t *testing.T) {
	const rule = `
title: specific github request
id: 99999999-9999-9999-9999-999999999999
detection:
  sel:
    created_at: 1780578968354
  condition: sel
`
	set, err := rules.Compile([]rules.File{file("gh.yml", rule)}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	asFloat, _, err := set.Match(context.Background(), map[string]any{"created_at": float64(1780578968354)})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(asFloat) != 0 {
		t.Log("sigma-go now handles float64 integers; the int normalisation " +
			"in internal/decode may be removable")
	}

	asInt, _, err := set.Match(context.Background(), map[string]any{"created_at": int(1780578968354)})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(asInt) != 1 {
		t.Errorf("int-valued field did not match: the decoder's number "+
			"normalisation no longer produces a matchable type (got %d matches)", len(asInt))
	}
}

func TestMatch_CancelledContextIsAnErrorNotARuleError(t *testing.T) {
	// Shutdown is not a rule problem, and counting it as one would make the
	// rule-error alarm fire on every deploy.
	set, _ := rules.Compile([]rules.File{file("ct.yml", stopLogging)}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := set.Match(ctx, map[string]any{"eventName": "StopLogging"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestMatch_UsesEveryLoadedRule(t *testing.T) {
	second := strings.Replace(strings.Replace(stopLogging,
		"11111111-1111-1111-1111-111111111111", "aaaaaaaa-1111-1111-1111-111111111111", 1),
		"CloudTrail Logging Disabled", "Second Rule", 1)
	set, err := rules.Compile([]rules.File{file("a.yml", stopLogging), file("b.yml", second)}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	matches, _, err := set.Match(context.Background(), map[string]any{
		"eventSource": "cloudtrail.amazonaws.com",
		"eventName":   "StopLogging",
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("matches = %d, want both rules to fire", len(matches))
	}
}

func TestCompile_WithFieldMappingConfig(t *testing.T) {
	// The operator-authored sigma-config.yml path.
	cfg, err := sigma.ParseConfig([]byte(`
title: test
fieldmappings:
  RuleField: actual_field
`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	set, err := rules.Compile([]rules.File{file("m.yml", `
title: mapped
id: bbbbbbbb-1111-1111-1111-111111111111
detection:
  sel:
    RuleField: hello
  condition: sel
`)}, []sigma.Config{cfg})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	matches, _, err := set.Match(context.Background(), map[string]any{"actual_field": "hello"})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("matches = %d, want 1 via the field mapping", len(matches))
	}
}
