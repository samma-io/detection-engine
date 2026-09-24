// Package rulecheck validates the rules committed in this repo.
//
// These tests are the CI gate on rule content. They exist because of one
// property of Sigma evaluation: a rule referencing a field the source does not
// emit does not error, it silently never matches. The engine reports it as
// loaded, /rules lists it, and no metric tells "no attacks" apart from "this
// rule cannot fire". A positive test case against a realistic event is the
// only thing that catches that before an incident does.
package rulecheck_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
	"gopkg.in/yaml.v3"

	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/rules"
	"github.com/samma-io/detection-engine/internal/source"
)

// testCase is one entry in a <rule>.tests.yml sidecar.
type testCase struct {
	Name     string         `yaml:"name"`
	Expected bool           `yaml:"expected"`
	Event    map[string]any `yaml:"event"`
}

const testsSuffix = ".tests.yml"

// ExamplesDir is the rules/ subdirectory that is never a lane. It carries
// org-specific example rules with placeholder values; see
// rules/examples/org-specific/README.md.
const ExamplesDir = "examples"

func rulesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(filepath.Dir(wd)), "rules")
}

// sourceDirs returns each source directory that holds rules.
func sourceDirs(t *testing.T) map[string]string {
	t.Helper()
	root := rulesDir(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		// rules/examples/ holds org-specific templates with placeholder values.
		// They are documentation, not part of the shipped ruleset: the rules
		// tarball excludes them and no lane prefix ever contains them.
		if e.IsDir() && e.Name() != ExamplesDir {
			out[e.Name()] = filepath.Join(root, e.Name())
		}
	}
	return out
}

// ruleFiles splits a source directory into rules, sidecars and the config.
func ruleFiles(t *testing.T, dir, configName string) (ruleKeys []string, config []sigma.Config) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		if strings.HasSuffix(name, testsSuffix) {
			continue
		}
		path := filepath.Join(dir, name)
		if name == configName {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := sigma.ParseConfig(body)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			config = append(config, cfg)
			continue
		}
		ruleKeys = append(ruleKeys, path)
	}
	sort.Strings(ruleKeys)
	return ruleKeys, config
}

// TestRules_EverySourceDirectoryHasARegistryEntry keeps the rules tree and the
// deployment roster in step. A directory with no registry entry is a rule set
// nothing evaluates.
func TestRules_EverySourceDirectoryHasARegistryEntry(t *testing.T) {
	for name := range sourceDirs(t) {
		if _, err := source.Lookup(name); err != nil {
			t.Errorf("rules/%s has no entry in the source registry: %v", name, err)
		}
	}
}

// TestRules_CompileForEverySource is the syntax and admission gate. It runs
// exactly what the engine runs at startup, so a rule that would stop a task
// from booting fails CI instead.
func TestRules_CompileForEverySource(t *testing.T) {
	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue // reported by the test above
		}
		keys, config := ruleFiles(t, dir, src.ConfigFile)
		if len(keys) == 0 {
			// Not a failure. A lane with no upstream writer yet has no rules,
			// and the engine deliberately refuses to start on an empty
			// ruleset -- so that lane must run with zero tasks until
			// rules exist.
			t.Logf("rules/%s has no rules yet; its engine must not be deployed", name)
			continue
		}

		files := make([]rules.File, 0, len(keys))
		for _, k := range keys {
			body, err := os.ReadFile(k)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, rules.File{Name: filepath.Base(k), Data: body})
		}
		if _, err := rules.Compile(files, config); err != nil {
			t.Errorf("rules/%s does not compile:\n%v", name, err)
		}
	}
}

// TestRules_EveryRuleHasAPositiveTestCase is the guard against the silent
// non-match.
func TestRules_EveryRuleHasAPositiveTestCase(t *testing.T) {
	var checked int

	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, config := ruleFiles(t, dir, src.ConfigFile)

		for _, rulePath := range keys {
			base := filepath.Base(rulePath)
			sidecarPath := strings.TrimSuffix(rulePath, filepath.Ext(rulePath)) + testsSuffix

			body, err := os.ReadFile(rulePath)
			if err != nil {
				t.Fatal(err)
			}

			sidecar, err := os.ReadFile(sidecarPath)
			if err != nil {
				t.Errorf("rules/%s/%s has no %s: a rule with no firing test case "+
					"cannot be distinguished from a rule that never matches",
					name, base, filepath.Base(sidecarPath))
				continue
			}

			var cases []testCase
			if err := yaml.Unmarshal(sidecar, &cases); err != nil {
				t.Errorf("%s: %v", sidecarPath, err)
				continue
			}

			var positives int
			for _, c := range cases {
				if c.Expected {
					positives++
				}
			}
			if positives == 0 {
				t.Errorf("rules/%s/%s has test cases but none expect a match; "+
					"at least one must prove the rule can fire", name, base)
				continue
			}

			// Compile this rule alone, so a match is attributable to it.
			set, err := rules.Compile([]rules.File{{Name: base, Data: body}}, config)
			if err != nil {
				t.Errorf("rules/%s/%s: %v", name, base, err)
				continue
			}

			for _, c := range cases {
				checked++
				// MatchView is what the engine feeds the evaluator, so the
				// test exercises the same path -- including the dotted-field
				// aliasing that most upstream rules depend on.
				matches, ruleErrs, err := set.Match(context.Background(), decode.MatchView(c.Event))
				if err != nil {
					t.Errorf("rules/%s/%s case %q: %v", name, base, c.Name, err)
					continue
				}
				for _, re := range ruleErrs {
					t.Errorf("rules/%s/%s case %q: rule errored: %v", name, base, c.Name, re.Err)
				}
				got := len(matches) > 0
				if got != c.Expected {
					t.Errorf("rules/%s/%s case %q: matched=%v, want %v",
						name, base, c.Name, got, c.Expected)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no rule test cases ran at all; the harness is not finding the rules tree")
	}
	t.Logf("ran %d rule test cases", checked)
}

// TestRules_IDsAreUniqueAcrossEverySource catches a copy-pasted id.
//
// Rule ids only have to be unique within a source for the engine to start, but
// the alert id is derived from them and alerts from every source land on one
// queue -- so a duplicate across sources would make two different detections
// look like the same alert downstream.
func TestRules_IDsAreUniqueAcrossEverySource(t *testing.T) {
	seen := map[string]string{}

	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, _ := ruleFiles(t, dir, src.ConfigFile)
		for _, k := range keys {
			body, err := os.ReadFile(k)
			if err != nil {
				t.Fatal(err)
			}
			rule, err := sigma.ParseRule(body)
			if err != nil {
				continue // reported by the compile test
			}
			where := name + "/" + filepath.Base(k)
			if prev, dup := seen[rule.ID]; dup {
				t.Errorf("rule id %s is used by both %s and %s", rule.ID, prev, where)
			}
			seen[rule.ID] = where
		}
	}
}

// TestRules_HaveTheMetadataTriageNeeds. A rule that fires at 3am with no
// description and no level is an alert nobody can act on.
func TestRules_HaveTheMetadataTriageNeeds(t *testing.T) {
	validLevels := map[string]bool{
		"informational": true, "low": true, "medium": true, "high": true, "critical": true,
	}

	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, _ := ruleFiles(t, dir, src.ConfigFile)
		for _, k := range keys {
			body, err := os.ReadFile(k)
			if err != nil {
				t.Fatal(err)
			}
			rule, err := sigma.ParseRule(body)
			if err != nil {
				continue
			}
			where := "rules/" + name + "/" + filepath.Base(k)

			if strings.TrimSpace(rule.ID) == "" {
				t.Errorf("%s has no id; the alert id is derived from it", where)
			}
			if strings.TrimSpace(rule.Title) == "" {
				t.Errorf("%s has no title", where)
			}
			if strings.TrimSpace(rule.Description) == "" {
				t.Errorf("%s has no description", where)
			}
			if !validLevels[strings.ToLower(rule.Level)] {
				t.Errorf("%s has level %q, want one of informational/low/medium/high/critical",
					where, rule.Level)
			}
		}
	}
}
