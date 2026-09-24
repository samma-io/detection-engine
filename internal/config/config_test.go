package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/samma-io/detection-engine/internal/config"
)

// env builds a getenv function from a map, so no test mutates process state.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func valid() map[string]string {
	return map[string]string{
		"ENGINE_LOG_SOURCE":      "aws",
		"ENGINE_QUEUE_URL":       "https://sqs.us-east-1.amazonaws.com/1/filtered-aws",
		"ENGINE_ALERT_QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/1/detections-alerts",
		"ENGINE_RULES_BUCKET":    "detection-rules-1-us-east-1",
		"AWS_REGION":             "us-east-1",
	}
}

func TestFromEnv_DefaultsAreAppliedForOptionalValues(t *testing.T) {
	c, err := config.FromEnv(env(valid()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.Workers != config.DefaultWorkers {
		t.Errorf("Workers = %d, want %d", c.Workers, config.DefaultWorkers)
	}
	if c.MaxObjectBytes != config.DefaultMaxObjectBytes {
		t.Errorf("MaxObjectBytes = %d, want %d", c.MaxObjectBytes, config.DefaultMaxObjectBytes)
	}
	if c.VisibilityBeat != config.DefaultVisibilityBeat {
		t.Errorf("VisibilityBeat = %v, want %v", c.VisibilityBeat, config.DefaultVisibilityBeat)
	}
	if c.MetricsAddr != config.DefaultMetricsAddr {
		t.Errorf("MetricsAddr = %q, want %q", c.MetricsAddr, config.DefaultMetricsAddr)
	}
}

func TestFromEnv_MissingRequiredVarsAreReportedTogether(t *testing.T) {
	// Reporting one at a time costs one failed deploy per variable.
	_, err := config.FromEnv(env(map[string]string{"ENGINE_LOG_SOURCE": "aws"}))
	if err == nil {
		t.Fatal("expected an error when every required var is unset")
	}
	for _, want := range []string{
		"ENGINE_QUEUE_URL", "ENGINE_ALERT_QUEUE_URL", "ENGINE_RULES_BUCKET", "AWS_REGION",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s, got:\n%v", want, err)
		}
	}
}

func TestFromEnv_UnknownLogSourceIsAStartupError(t *testing.T) {
	kv := valid()
	kv["ENGINE_LOG_SOURCE"] = "splunk"
	if _, err := config.FromEnv(env(kv)); err == nil {
		t.Fatal("an unknown log source must not start")
	}
}

func TestFromEnv_UnsetLogSourceIsAStartupError(t *testing.T) {
	kv := valid()
	delete(kv, "ENGINE_LOG_SOURCE")
	if _, err := config.FromEnv(env(kv)); err == nil {
		t.Fatal("an unset log source must not default to a source")
	}
}

func TestFromEnv_MalformedNumberIsAnErrorNotADefault(t *testing.T) {
	// Falling back to the default here would run 4 workers and look
	// deliberate, hiding a typo in the task definition.
	kv := valid()
	kv["ENGINE_WORKERS"] = "eight"
	_, err := config.FromEnv(env(kv))
	if err == nil {
		t.Fatal("expected an error for a non-integer worker count")
	}
	if !strings.Contains(err.Error(), "ENGINE_WORKERS") {
		t.Errorf("error should name the variable, got: %v", err)
	}
}

func TestFromEnv_MalformedDurationIsAnError(t *testing.T) {
	kv := valid()
	kv["ENGINE_VISIBILITY_HEARTBEAT"] = "60"
	if _, err := config.FromEnv(env(kv)); err == nil {
		t.Fatal("expected an error for a bare number as a duration")
	}
}

func TestFromEnv_OutOfRangeDecodeRatioIsAnError(t *testing.T) {
	kv := valid()
	kv["ENGINE_MAX_DECODE_ERROR_RATIO"] = "5"
	if _, err := config.FromEnv(env(kv)); err == nil {
		t.Fatal("a ratio above 1 is meaningless and must not start")
	}
}

func TestFromEnv_ZeroWorkersIsAnError(t *testing.T) {
	// Zero workers is the quietest possible failure: the task runs, reports
	// healthy, and drains nothing.
	kv := valid()
	kv["ENGINE_WORKERS"] = "0"
	if _, err := config.FromEnv(env(kv)); err == nil {
		t.Fatal("zero workers must not start")
	}
}

func TestRulePrefix_JoinsPrefixAndSourceWithASlash(t *testing.T) {
	kv := valid()
	kv["ENGINE_RULES_PREFIX"] = "rules"
	c, err := config.FromEnv(env(kv))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	// "rulesaws/" would list nothing and load zero rules.
	if got, want := c.RulePrefix(), "rules/aws/"; got != want {
		t.Errorf("RulePrefix() = %q, want %q", got, want)
	}
}

func TestRulePrefix_EmptyPrefixIsJustTheSource(t *testing.T) {
	c, err := config.FromEnv(env(valid()))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got, want := c.RulePrefix(), "aws/"; got != want {
		t.Errorf("RulePrefix() = %q, want %q", got, want)
	}
}

func TestFromEnv_OverridesAreParsed(t *testing.T) {
	kv := valid()
	kv["ENGINE_WORKERS"] = "8"
	kv["ENGINE_VISIBILITY_HEARTBEAT"] = "45s"
	kv["ENGINE_MAX_DECODE_ERROR_RATIO"] = "0.5"
	c, err := config.FromEnv(env(kv))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.Workers != 8 {
		t.Errorf("Workers = %d, want 8", c.Workers)
	}
	if c.VisibilityBeat != 45*time.Second {
		t.Errorf("VisibilityBeat = %v, want 45s", c.VisibilityBeat)
	}
	if c.MaxDecodeErrorRate != 0.5 {
		t.Errorf("MaxDecodeErrorRate = %v, want 0.5", c.MaxDecodeErrorRate)
	}
}
