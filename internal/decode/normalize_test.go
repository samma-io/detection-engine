package decode_test

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/samma-io/detection-engine/internal/decode"
)

func decodeOne(t *testing.T, line string) map[string]any {
	t.Helper()
	var got map[string]any
	err := decode.Records(context.Background(), bytes.NewReader([]byte(line+"\n")), 0,
		func(_ int, e map[string]any) error { got = e; return nil },
		func(_ int, err error) error { t.Fatalf("unexpected bad record: %v", err); return nil },
	)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	return got
}

func TestNormalize_IntegralNumbersBecomeIntNotFloat(t *testing.T) {
	// GitHub audit records carry created_at as epoch millis. As a float64 it
	// stringifies to "1.780578968354e+12" and an equality rule on the literal
	// integer silently never matches.
	e := decodeOne(t, `{"created_at":1780578968354,"status_code":204}`)
	if got, ok := e["created_at"].(int); !ok || got != 1780578968354 {
		t.Errorf("created_at = %v (%T), want int 1780578968354", e["created_at"], e["created_at"])
	}
	if got, ok := e["status_code"].(int); !ok || got != 204 {
		t.Errorf("status_code = %v (%T), want int 204", e["status_code"], e["status_code"])
	}
}

func TestNormalize_FractionalNumbersStayFloat64(t *testing.T) {
	// float64 is the kind sigma-go's numeric coercion accepts alongside int;
	// json.Number would panic on a |gt modifier.
	e := decodeOne(t, `{"score":7.5}`)
	if got, ok := e["score"].(float64); !ok || got != 7.5 {
		t.Errorf("score = %v (%T), want float64 7.5", e["score"], e["score"])
	}
}

func TestNormalize_NoJSONNumberSurvivesDecoding(t *testing.T) {
	// Leaving a json.Number in the event is not a near miss: a |gt modifier
	// against one panics with "interface conversion: json.Number, not
	// string", which in a Fargate task means a crash loop with detection off.
	e := decodeOne(t, `{"a":1,"b":{"c":2},"d":[3,{"e":4}]}`)
	assertNoJSONNumber(t, "", e)
}

func assertNoJSONNumber(t *testing.T, path string, v any) {
	t.Helper()
	switch tv := v.(type) {
	case map[string]any:
		for k, val := range tv {
			assertNoJSONNumber(t, path+"."+k, val)
		}
	case []any:
		for _, val := range tv {
			assertNoJSONNumber(t, path+"[]", val)
		}
	default:
		if reflect.TypeOf(v) != nil && reflect.TypeOf(v).String() == "json.Number" {
			t.Errorf("%s is a json.Number, which panics numeric modifiers", path)
		}
	}
}

func TestNormalize_NestedNumbersAreNormalisedToo(t *testing.T) {
	e := decodeOne(t, `{"actor_location":{"lat":5},"userIdentity":{"seq":9000000000}}`)
	loc := e["actor_location"].(map[string]any)
	if _, ok := loc["lat"].(int); !ok {
		t.Errorf("nested lat = %T, want int", loc["lat"])
	}
	id := e["userIdentity"].(map[string]any)
	if _, ok := id["seq"].(int); !ok {
		t.Errorf("nested seq = %T, want int", id["seq"])
	}
}

// ---------------------------------------------------------------- match view

func TestMatchView_AddsDottedAliasesForNestedFields(t *testing.T) {
	// The reason this package has a match view at all: sigma-go's field lookup
	// is one flat map index, so a rule written userIdentity.type never sees a
	// nested object.
	event := map[string]any{
		"eventName":    "StopLogging",
		"userIdentity": map[string]any{"type": "AssumedRole", "accountId": "1"},
	}
	view := decode.MatchView(event)

	if view["userIdentity.type"] != "AssumedRole" {
		t.Errorf("userIdentity.type = %v, want AssumedRole", view["userIdentity.type"])
	}
	if view["eventName"] != "StopLogging" {
		t.Errorf("top-level field lost: %v", view["eventName"])
	}
	// The nested original stays, so a rule can target either shape.
	if _, ok := view["userIdentity"]; !ok {
		t.Error("nested original should still be present")
	}
}

func TestMatchView_DoesNotMutateTheEvent(t *testing.T) {
	// The event goes into the alert. If aliases leaked into it, every alert
	// would carry fields the source never emitted and be twice the size.
	event := map[string]any{"userIdentity": map[string]any{"type": "Root"}}
	_ = decode.MatchView(event)

	if len(event) != 1 {
		t.Errorf("event gained keys: %v", event)
	}
	if _, ok := event["userIdentity.type"]; ok {
		t.Error("alias leaked into the event that goes into the alert")
	}
}

func TestMatchView_FlattensDeeply(t *testing.T) {
	event := map[string]any{"a": map[string]any{"b": map[string]any{"c": "deep"}}}
	view := decode.MatchView(event)
	if view["a.b.c"] != "deep" {
		t.Errorf("a.b.c = %v, want deep", view["a.b.c"])
	}
	if view["a.b"] == nil {
		t.Error("intermediate alias a.b should also exist")
	}
}

func TestMatchView_ArrayOfObjectsCollapsesIntoOneAlias(t *testing.T) {
	// CloudTrail's resources is [{ARN: a}, {ARN: b}] and rules are written
	// resources.ARN. sigma-go expands a slice-valued field across its
	// elements, so collecting the leaves into one slice is enough.
	event := map[string]any{"resources": []any{
		map[string]any{"ARN": "arn:a"},
		map[string]any{"ARN": "arn:b"},
	}}
	view := decode.MatchView(event)

	got, ok := view["resources.ARN"].([]any)
	if !ok {
		t.Fatalf("resources.ARN = %v (%T), want a slice", view["resources.ARN"], view["resources.ARN"])
	}
	if len(got) != 2 || got[0] != "arn:a" || got[1] != "arn:b" {
		t.Errorf("resources.ARN = %v, want [arn:a arn:b]", got)
	}
}

func TestMatchView_ARealFieldIsNeverShadowedByAnAlias(t *testing.T) {
	// If the source emits a literal dotted key, that field wins. An alias must
	// never change the meaning of a field that actually exists.
	event := map[string]any{
		"userIdentity.type": "REAL",
		"userIdentity":      map[string]any{"type": "ALIAS"},
	}
	view := decode.MatchView(event)
	if view["userIdentity.type"] != "REAL" {
		t.Errorf("userIdentity.type = %v, want the real field to win", view["userIdentity.type"])
	}
}

func TestMatchView_SharesLeafValuesRatherThanDeepCopying(t *testing.T) {
	// Documents the contract that makes the view cheap: leaves are shared, so
	// nothing may mutate a value reached through the view.
	nested := map[string]any{"type": "Root"}
	event := map[string]any{"userIdentity": nested}
	view := decode.MatchView(event)

	if got := view["userIdentity"].(map[string]any); &got != &nested && got["type"] != "Root" {
		t.Error("expected the nested map to be shared")
	}
}
