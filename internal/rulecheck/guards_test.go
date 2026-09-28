package rulecheck_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
	"gopkg.in/yaml.v3"

	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/rules"
	"github.com/samma-io/detection-engine/internal/source"
)

// TestRules_LaneDirectoriesContainOnlyRulesAndSidecars stops a stray file from
// crash-looping a lane.
//
// rules.Load treats *every* .yml and .yaml under a source prefix as a rule, and
// Compile makes one unparseable file fatal, so the task refuses to start. CI
// syncs this tree to the bucket recursively, which means a lock file, a
// manifest written to the wrong directory, or a vendored subdirectory does not
// fail here -- it fails at the next container start, in every task of that
// lane at once, with the engine correctly refusing to run.
//
// That is the right runtime behaviour and the wrong place to find out. This
// test is the place to find out.
func TestRules_LaneDirectoriesContainOnlyRulesAndSidecars(t *testing.T) {
	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue // reported by TestRules_EverySourceDirectoryHasARegistryEntry
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}

		ruleBases := map[string]bool{}
		var sidecars []string

		for _, e := range entries {
			where := "rules/" + name + "/" + e.Name()

			// A subdirectory syncs to the bucket and every .yml under it comes
			// back from List under this lane's prefix.
			if e.IsDir() {
				t.Errorf("%s is a directory; rules.Load lists the lane prefix "+
					"recursively, so every .yml beneath it would be loaded as a rule "+
					"and would crash-loop this lane at next container start", where)
				continue
			}

			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext != ".yml" && ext != ".yaml" {
				// Non-YAML is skipped by the loader with a warning, so it cannot
				// break a start. README.md is expected; anything else is a
				// surprise worth naming.
				if e.Name() != "README.md" {
					t.Logf("%s is not YAML; the loader will skip it with a warning", where)
				}
				continue
			}

			if e.Name() == src.ConfigFile {
				continue
			}
			if strings.HasSuffix(e.Name(), testsSuffix) {
				sidecars = append(sidecars, e.Name())
				continue
			}

			// Anything else the loader will load as a rule, so that is what it
			// counts as here. Whether it is a *valid* rule is
			// TestRules_CompileForEverySource's job, through the engine's own
			// admission path -- no need to render a second, weaker verdict.
			ruleBases[strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))] = true
		}

		// A sidecar whose rule was renamed away is dead weight that still looks
		// like coverage in a directory listing.
		for _, s := range sidecars {
			stem := strings.TrimSuffix(s, testsSuffix)
			if !ruleBases[stem] {
				t.Errorf("rules/%s/%s has no matching rule file; either the rule was "+
					"renamed and the sidecar was not, or the rule was deleted and its "+
					"tests were left behind", name, s)
			}
		}
	}
}

// TestRules_DoNotFireOnABareEnvelope catches the catastrophically over-broad
// rule.
//
// Every record in the filtered bucket carries at least `source`. A rule that
// matches an event containing *only* that is matching every record on the
// lane, which is not a detection -- it is a self-inflicted denial of service on
// the alert queue, bounded only by ENGINE_MAX_ALERTS_PER_OBJECT.
//
// The shape that gets here is `condition: selection and not 1 of filter*`,
// where the filters silently never match. See
// TestRules_NoGlobsInDetectionValues for the most common reason they don't.
func TestRules_DoNotFireOnABareEnvelope(t *testing.T) {
	var checked int

	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, config := ruleFiles(t, dir, src.ConfigFile)

		for _, rulePath := range keys {
			base := filepath.Base(rulePath)
			body, err := os.ReadFile(rulePath)
			if err != nil {
				t.Fatal(err)
			}

			// Compiled alone, so a match is attributable to this rule.
			set, err := rules.Compile([]rules.File{{Name: base, Data: body}}, config)
			if err != nil {
				continue // reported by TestRules_CompileForEverySource
			}

			envelope := map[string]any{"source": name}
			matches, _, err := set.Match(context.Background(), decode.MatchView(envelope))
			if err != nil {
				t.Errorf("rules/%s/%s: %v", name, base, err)
				continue
			}
			checked++
			if len(matches) > 0 {
				t.Errorf("rules/%s/%s fires on an event containing nothing but "+
					"source=%q. It will alert on every record on this lane. The usual "+
					"cause is a `not` over a filter that never matches.", name, base, name)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no rules were checked; the harness is not finding the rules tree")
	}
	t.Logf("checked %d rules against a bare envelope", checked)
}

// feedPinningLanes are the lanes whose sigma-config documents that several
// feeds share the prefix and do NOT share a field vocabulary, so a rule that
// does not pin `feed` can match a record from a feed it was never written for.
//
// gcp and workspace also carry a `feed`, but their records share one shape
// across feeds (protoPayload, events[]), so pinning is a judgement call there
// rather than a correctness requirement. Only the lanes that make the contract
// are enforced.
var feedPinningLanes = map[string]string{
	"slack":       "accesslogs and integrationlogs share no fields at all",
	"onepassword": "itemusages, signinattempts and auditevents overlap on action and uuid",
	"cloudflare":  "audit, access and firewall all carry `action` with unrelated meanings",
}

// TestRules_MultiFeedLanesPinTheFeed enforces what those configs already say.
func TestRules_MultiFeedLanesPinTheFeed(t *testing.T) {
	for name, dir := range sourceDirs(t) {
		why, enforced := feedPinningLanes[name]
		if !enforced {
			continue
		}
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, _ := ruleFiles(t, dir, src.ConfigFile)

		for _, rulePath := range keys {
			body, err := os.ReadFile(rulePath)
			if err != nil {
				t.Fatal(err)
			}
			rule, err := sigma.ParseRule(body)
			if err != nil {
				continue
			}
			if !referencesField(rule, "feed") {
				t.Errorf("rules/%s/%s does not pin `feed`, but on this lane %s -- "+
					"so this rule can match a record from a feed it was never written "+
					"for. Add feed to a selection.", name, filepath.Base(rulePath), why)
			}
		}
	}
}

// TestRules_TestEventsCarryTheLaneEnvelope keeps sidecar events realistic.
//
// Every record the engine sees carries `source`, because Vector stamps it. A
// test event without one is not a record the engine could ever be given, and a
// rule proven only against an unrealistic event is not proven. It is also the
// first thing a generated stub gets wrong.
func TestRules_TestEventsCarryTheLaneEnvelope(t *testing.T) {
	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, _ := ruleFiles(t, dir, src.ConfigFile)

		for _, rulePath := range keys {
			sidecarPath := strings.TrimSuffix(rulePath, filepath.Ext(rulePath)) + testsSuffix
			sidecar, err := os.ReadFile(sidecarPath)
			if err != nil {
				continue // reported by TestRules_EveryRuleHasAPositiveTestCase
			}
			var cases []testCase
			if err := yaml.Unmarshal(sidecar, &cases); err != nil {
				continue
			}
			for _, c := range cases {
				got, ok := c.Event["source"]
				if !ok {
					t.Errorf("rules/%s/%s case %q has no `source`; Vector stamps one on "+
						"every record, so this event could not occur",
						name, filepath.Base(sidecarPath), c.Name)
					continue
				}
				if s, _ := got.(string); s != name {
					t.Errorf("rules/%s/%s case %q has source=%v, want %q",
						name, filepath.Base(sidecarPath), c.Name, got, name)
				}
			}
		}
	}
}

// referencesField reports whether any search in the rule matches on field.
func referencesField(rule sigma.Rule, field string) bool {
	for _, search := range rule.Detection.Searches {
		for _, matcher := range search.EventMatchers {
			for _, fm := range matcher {
				if strings.EqualFold(fm.Field, field) {
					return true
				}
			}
		}
	}
	return false
}
