package rulecheck_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/rules"
	"github.com/samma-io/detection-engine/internal/source"
)

// TestRules_DoNotSemanticallyDuplicateEachOther catches two rules that fire on
// the same event.
//
// Nothing else notices this. TestRules_IDsAreUniqueAcrossEverySource compares
// ids, and a duplicate imported from upstream has a different id by
// construction -- so the pair passes every existing gate while producing two
// alerts, two GitHub issues and two pages for one thing that happened.
//
// It is the specific failure mode of importing: upstream corpora overlap each
// other and overlap what we wrote by hand, and the overlap is invisible in a
// diff of two separate files.
//
// Some overlap is deliberate -- a general rule plus a higher-severity special
// case of it. Those go in overlappingRules with the reason, so that an
// intentional pair is a recorded decision rather than an unexamined one.
var overlappingRules = map[string]string{
	"root_account_activity.yml+root_activity_in_management_account.yml": "" +
		"deliberate: root anywhere at high, plus the management-account case at " +
		"critical. Narrowing the general rule would trade root coverage in " +
		"thirteen accounts for a severity bump in two.",
	"console_login_without_mfa.yml+root_account_activity.yml": "" +
		"a root console login has no MFA recorded, so both legitimately apply: " +
		"one says who, the other says how.",
	"console_login_without_mfa.yml+root_activity_in_management_account.yml": "" +
		"same pair as above, in a management account.",
}

func TestRules_DoNotSemanticallyDuplicateEachOther(t *testing.T) {
	for name, dir := range sourceDirs(t) {
		src, err := source.Lookup(name)
		if err != nil {
			continue
		}
		keys, config := ruleFiles(t, dir, src.ConfigFile)
		if len(keys) < 2 {
			continue
		}

		var files []rules.File
		for _, k := range keys {
			body, err := os.ReadFile(k)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, rules.File{Name: filepath.Base(k), Data: body})
		}
		set, err := rules.Compile(files, config)
		if err != nil {
			continue // reported by TestRules_CompileForEverySource
		}

		reported := map[string]bool{}
		for _, k := range keys {
			sidecar := strings.TrimSuffix(k, filepath.Ext(k)) + testsSuffix
			body, err := os.ReadFile(sidecar)
			if err != nil {
				continue
			}
			var cases []testCase
			if err := yaml.Unmarshal(body, &cases); err != nil {
				continue
			}

			for _, c := range cases {
				if !c.Expected {
					continue
				}
				matches, _, err := set.Match(context.Background(), decode.MatchView(c.Event))
				if err != nil || len(matches) < 2 {
					continue
				}
				for _, pair := range pairsOf(matches) {
					if reported[pair] || overlappingRules[pair] != "" {
						continue
					}
					reported[pair] = true
					t.Errorf("rules/%s: %s both fire on one event (from %s).\n"+
						"    That is two alerts with two ids for one thing that happened. "+
						"Delete the weaker rule, narrow one of them, or -- if the overlap "+
						"is deliberate -- add\n      %q\n    to overlappingRules with the reason.",
						name, strings.ReplaceAll(pair, "+", " and "), filepath.Base(sidecar), pair)
				}
			}
		}
	}
}

// pairsOf returns every unordered pair of matched rule files, keyed stably so
// the allowlist does not depend on match order.
func pairsOf(matches []rules.Match) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, filepath.Base(m.File))
	}
	sort.Strings(names)
	var out []string
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			out = append(out, fmt.Sprintf("%s+%s", names[i], names[j]))
		}
	}
	return out
}
