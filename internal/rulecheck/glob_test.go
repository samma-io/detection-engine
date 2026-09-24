package rulecheck_test

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
	"gopkg.in/yaml.v3"

	"github.com/samma-io/detection-engine/internal/source"
)

// TestRules_NoGlobsInDetectionValues is the guard against the one silent
// non-match that compiling cannot catch.
//
// The Sigma spec says `*` is a wildcard. sigma-go does not implement that for
// values: the default comparator is
//
//	strings.EqualFold(CoerceString(actual), CoerceString(expected))
//
// and contains/startswith/endswith are plain strings.Contains/HasPrefix/
// HasSuffix. There is no glob translation anywhere in the library. The two
// path.Match calls in evaluator/evaluate_search.go match *condition* field-name
// patterns -- `1 of selection_*` -- which is why those are fine and only values
// are checked here.
//
// So a `*` in a value is a literal asterisk, and the rule compiles, loads,
// appears on /rules, and is wrong forever. Which way it is wrong depends on
// where the search sits in the condition, and both ways are bad:
//
//   - in a selection, the rule never fires;
//   - in a filter under `not`, the filter never matches, so the negation always
//     holds and the rule fires on everything the selection matched.
//
// The second is the dangerous one, because it looks like the rule works.
//
// Not every asterisk is a bug -- a rule can legitimately search for a literal
// `*`, as in the IAM policy ARN "arn:aws:s3:::bucket/*". Those go in
// testdata/wildcard_exceptions.yml with a reason, rather than being waved
// through by a blanket rule, because the two cases are indistinguishable
// without knowing what the source emits.
func TestRules_NoGlobsInDetectionValues(t *testing.T) {
	allowed := loadWildcardExceptions(t)
	var checked int

	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue // reported by TestRules_EverySourceDirectoryHasARegistryEntry
		}
		keys, _ := ruleFiles(t, dir, src.ConfigFile)

		for _, rulePath := range keys {
			body, err := os.ReadFile(rulePath)
			if err != nil {
				t.Fatal(err)
			}
			rule, err := sigma.ParseRule(body)
			if err != nil {
				continue // reported by TestRules_CompileForEverySource
			}

			where := "rules/" + name + "/" + filepath.Base(rulePath)
			negated := negatedSearches(rule)

			for searchName, search := range rule.Detection.Searches {
				for _, matcher := range search.EventMatchers {
					for _, fm := range matcher {
						if comparatorIgnoresGlobs(fm.Modifiers) {
							continue
						}
						for _, v := range fm.Values {
							s, ok := v.(string)
							if !ok || !strings.ContainsAny(s, "*?") {
								continue
							}
							checked++
							if allowed[exception{RuleID: rule.ID, Field: fm.Field}] {
								continue
							}
							t.Errorf("%s: search %q field %q value %q contains a "+
								"wildcard, but sigma-go matches values literally, so %s\n"+
								"    Rewrite it with |re (a real regex), narrow it to a "+
								"literal with |contains/|startswith/|endswith, or -- if the\n"+
								"    asterisk really is part of the value -- add rule id %s "+
								"field %q to internal/rulecheck/testdata/wildcard_exceptions.yml.",
								where, searchName, fm.Field, s,
								globConsequence(negated[searchName]), rule.ID, fm.Field)
						}
					}
				}
			}
		}
	}

	t.Logf("checked %d wildcard-bearing values", checked)
}

func globConsequence(isNegated bool) string {
	if isNegated {
		return "this search sits under a `not`: it will never match, the negation " +
			"will always hold, and the rule will OVER-FIRE on everything its " +
			"selection matched"
	}
	return "this rule will NEVER fire"
}

// comparatorIgnoresGlobs reports whether the trailing comparator makes an
// asterisk meaningful rather than literal. |re takes a real regex, where `*` is
// a quantifier, and |base64 encodes the value before comparing so the asterisk
// never reaches a matcher as itself.
func comparatorIgnoresGlobs(mods []string) bool {
	for _, m := range mods {
		if m == "re" || m == "base64" {
			return true
		}
	}
	return false
}

// negatedSearches returns the searches reachable through a `not` in any
// condition, so the failure message can say which way the rule is broken.
//
// `1 of filter_*` and `all of filter_*` are resolved with path.Match, the same
// way the evaluator resolves them.
func negatedSearches(rule sigma.Rule) map[string]bool {
	out := map[string]bool{}

	var walk func(expr sigma.SearchExpr, under bool)
	walk = func(expr sigma.SearchExpr, under bool) {
		switch e := expr.(type) {
		case sigma.And:
			for _, sub := range e {
				walk(sub, under)
			}
		case sigma.Or:
			for _, sub := range e {
				walk(sub, under)
			}
		case sigma.Not:
			walk(e.Expr, !under)
		case sigma.SearchIdentifier:
			if under {
				out[e.Name] = true
			}
		case sigma.OneOfIdentifier:
			if under {
				out[e.Ident.Name] = true
			}
		case sigma.AllOfIdentifier:
			if under {
				out[e.Ident.Name] = true
			}
		case sigma.OneOfPattern:
			markPattern(rule, e.Pattern, under, out)
		case sigma.AllOfPattern:
			markPattern(rule, e.Pattern, under, out)
		case sigma.OneOfThem, sigma.AllOfThem:
			if under {
				for name := range rule.Detection.Searches {
					out[name] = true
				}
			}
		}
	}

	for _, cond := range rule.Detection.Conditions {
		walk(cond.Search, false)
	}
	return out
}

func markPattern(rule sigma.Rule, pattern string, under bool, out map[string]bool) {
	if !under {
		return
	}
	for name := range rule.Detection.Searches {
		if ok, _ := path.Match(pattern, name); ok {
			out[name] = true
		}
	}
}

type exception struct {
	RuleID string
	Field  string
}

type exceptionFile struct {
	RuleID string `yaml:"rule_id"`
	Field  string `yaml:"field"`
	Reason string `yaml:"reason"`
}

func loadWildcardExceptions(t *testing.T) map[exception]bool {
	t.Helper()

	body, err := os.ReadFile(filepath.Join("testdata", "wildcard_exceptions.yml"))
	if err != nil {
		if os.IsNotExist(err) {
			return map[exception]bool{}
		}
		t.Fatal(err)
	}

	var entries []exceptionFile
	if err := yaml.Unmarshal(body, &entries); err != nil {
		t.Fatalf("testdata/wildcard_exceptions.yml: %v", err)
	}

	out := make(map[exception]bool, len(entries))
	for i, e := range entries {
		// An exception with no reason is an exception nobody can review later.
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("testdata/wildcard_exceptions.yml entry %d (rule %s, field %s) has no reason",
				i, e.RuleID, e.Field)
		}
		out[exception{RuleID: e.RuleID, Field: e.Field}] = true
	}
	return out
}
