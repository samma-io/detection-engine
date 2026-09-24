package rules_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/samma-io/detection-engine/internal/rules"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeStore is an in-memory S3.
type fakeStore struct {
	objects map[string]string
	listErr error
	getErr  error
	listed  []string
}

func (f *fakeStore) List(_ context.Context, _, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.listed = append(f.listed, prefix)
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (f *fakeStore) Get(_ context.Context, _, key string) (io.ReadCloser, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	body, ok := f.objects[key]
	if !ok {
		return nil, errors.New("no such key: " + key)
	}
	return io.NopCloser(strings.NewReader(body)), nil
}

func TestLoad_CompilesEveryRuleUnderThePrefix(t *testing.T) {
	store := &fakeStore{objects: map[string]string{
		"aws/cloudtrail_stop_logging.yml": stopLogging,
		"aws/sigma-config.yml":            "title: aws\nfieldmappings: {}\n",
		// A different source's rules must not be picked up.
		"github/some_rule.yml": stopLogging,
	}}

	res, err := rules.Load(context.Background(), store, "rules-bucket", "aws/", "sigma-config.yml", quiet())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Set.Len() != 1 {
		t.Fatalf("rules = %d, want 1", res.Set.Len())
	}
	if len(res.ConfigKeys) != 1 {
		t.Errorf("configs = %v, want the one sigma-config.yml", res.ConfigKeys)
	}
	if store.listed[0] != "aws/" {
		t.Errorf("listed prefix %q, want aws/", store.listed[0])
	}
}

func TestLoad_ZeroRulesIsAStartupError(t *testing.T) {
	// The failure this service most needs to avoid: a task that starts with no
	// rules drains its queue, matches nothing, and makes depth go DOWN.
	store := &fakeStore{objects: map[string]string{
		"aws/sigma-config.yml": "title: aws\n",
	}}
	_, err := rules.Load(context.Background(), store, "b", "aws/", "sigma-config.yml", quiet())
	if !errors.Is(err, rules.ErrNoRules) {
		t.Fatalf("err = %v, want ErrNoRules", err)
	}
}

func TestLoad_EmptyPrefixIsAStartupError(t *testing.T) {
	store := &fakeStore{objects: map[string]string{}}
	_, err := rules.Load(context.Background(), store, "b", "slack/", "sigma-config.yml", quiet())
	if !errors.Is(err, rules.ErrNoRules) {
		t.Fatalf("err = %v, want ErrNoRules", err)
	}
}

func TestLoad_ListFailureIsAStartupError(t *testing.T) {
	// The rules bucket is a hard dependency for task start. That is the
	// fail-closed behaviour we want, and it is why the alarm is on task-start
	// failure and readiness rather than on queue depth.
	store := &fakeStore{listErr: errors.New("AccessDenied")}
	if _, err := rules.Load(context.Background(), store, "b", "aws/", "sigma-config.yml", quiet()); err == nil {
		t.Fatal("a rules-bucket failure must not start the engine")
	}
}

func TestLoad_ConfigIsAppliedToTheRules(t *testing.T) {
	store := &fakeStore{objects: map[string]string{
		"aws/sigma-config.yml": "title: aws\nfieldmappings:\n  RuleField: actual_field\n",
		"aws/mapped.yml": `
title: mapped
id: cccccccc-1111-1111-1111-111111111111
detection:
  sel:
    RuleField: hello
  condition: sel
`,
	}}
	res, err := rules.Load(context.Background(), store, "b", "aws/", "sigma-config.yml", quiet())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	matches, _, err := res.Set.Match(context.Background(), map[string]any{"actual_field": "hello"})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(matches) != 1 {
		t.Error("the config's field mapping was not applied to the loaded rule")
	}
}

func TestLoad_NonYAMLObjectsAreSkipped(t *testing.T) {
	store := &fakeStore{objects: map[string]string{
		"aws/rule.yml":  stopLogging,
		"aws/README.md": "not a rule",
	}}
	res, err := rules.Load(context.Background(), store, "b", "aws/", "sigma-config.yml", quiet())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Set.Len() != 1 {
		t.Errorf("rules = %d, want 1", res.Set.Len())
	}
}

func TestLoad_AnOversizeObjectIsRejectedRatherThanParsed(t *testing.T) {
	// Guards against the rules prefix accidentally pointing at log data.
	store := &fakeStore{objects: map[string]string{
		"aws/huge.yml": strings.Repeat("x", 2<<20),
	}}
	_, err := rules.Load(context.Background(), store, "b", "aws/", "sigma-config.yml", quiet())
	if err == nil {
		t.Fatal("a multi-megabyte 'rule' must be rejected")
	}
	if !strings.Contains(err.Error(), "log data") {
		t.Errorf("error should hint at the likely cause, got: %v", err)
	}
}

func TestLoad_LevelCountsFeedTheGauge(t *testing.T) {
	store := &fakeStore{objects: map[string]string{"aws/r.yml": stopLogging}}
	res, err := rules.Load(context.Background(), store, "b", "aws/", "sigma-config.yml", quiet())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := res.LevelCounts()["high"]; got != 1 {
		t.Errorf("LevelCounts()[high] = %d, want 1", got)
	}
}

// TestMatch_IsSafeForConcurrentUse pins an unasserted internal detail of
// sigma-go.
//
// Every worker goroutine shares one *Set, so concurrent Matches on the same
// compiled evaluator must be race-free. It is today -- Matches and its search
// helpers take value receivers and allocate their results per call -- but that
// is a property of the dependency, not a documented guarantee, and a future
// lazy-evaluation optimisation could start caching on the receiver. Run under
// -race, this test is the thing that would notice a dependency bump breaking
// it, which would otherwise show up as corrupted alerts under load.
func TestMatch_IsSafeForConcurrentUse(t *testing.T) {
	set, err := rules.Compile([]rules.File{file("ct.yml", stopLogging)}, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				event := map[string]any{
					"eventSource": "cloudtrail.amazonaws.com",
					"eventName":   "StopLogging",
					"worker":      n,
				}
				matches, ruleErrs, err := set.Match(context.Background(), event)
				if err != nil {
					t.Errorf("Match: %v", err)
					return
				}
				if len(ruleErrs) != 0 {
					t.Errorf("rule errors: %v", ruleErrs)
					return
				}
				if len(matches) != 1 {
					t.Errorf("matches = %d, want 1", len(matches))
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
