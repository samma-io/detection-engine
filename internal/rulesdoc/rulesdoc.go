package rulesdoc

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	"gopkg.in/yaml.v3"
)

// OutputPath is where the rendered catalogue is committed, relative to the
// repository root.
const OutputPath = "docs/RULES.md"

const testsSuffix = ".tests.yml"

// ExamplesDir is the rules/ subdirectory that is documentation rather than a
// lane; see rules/examples/org-specific/README.md.
const ExamplesDir = "examples"

// levelOrder ranks severities most-urgent first. A catalogue sorted
// alphabetically would open on "critical" only by accident.
var levelOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4,
}

var levelBadge = map[string]string{
	"critical":      "🔴",
	"high":          "🟠",
	"medium":        "🟡",
	"low":           "🔵",
	"informational": "⚪",
}

// Rule is one rule as the catalogue presents it.
type Rule struct {
	Lane           string
	File           string
	ID             string
	Title          string
	Level          string
	Status         string
	Description    string
	FiresWhen      string
	FalsePositives []string
	Tags           []string
	References     []string
	TestCases      int
	FiringCases    int
}

// Render builds the catalogue from the rules tree at rulesDir.
func Render(rulesDir string) (string, error) {
	lanes, err := os.ReadDir(rulesDir)
	if err != nil {
		return "", err
	}

	var all []Rule
	for _, lane := range lanes {
		// examples/ holds org-specific templates, not a lane. They are not
		// shipped and must not appear in the catalogue as if they were.
		if !lane.IsDir() || lane.Name() == ExamplesDir {
			continue
		}
		rules, err := loadLane(rulesDir, lane.Name())
		if err != nil {
			return "", err
		}
		all = append(all, rules...)
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Lane != all[j].Lane {
			return all[i].Lane < all[j].Lane
		}
		li, lj := levelOrder[all[i].Level], levelOrder[all[j].Level]
		if li != lj {
			return li < lj
		}
		return all[i].Title < all[j].Title
	})

	var b strings.Builder
	writePreamble(&b, all)
	writeSummary(&b, all)
	writeRules(&b, all)
	return b.String(), nil
}

func loadLane(rulesDir, lane string) ([]Rule, error) {
	dir := filepath.Join(rulesDir, lane)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []Rule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		if strings.HasSuffix(name, testsSuffix) || strings.HasPrefix(name, "sigma-config") {
			continue
		}

		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		rule, err := sigma.ParseRule(body)
		if err != nil {
			// Not this tool's job to report: TestRules_CompileForEverySource
			// fails on it through the engine's own admission path.
			continue
		}

		total, firing := countCases(filepath.Join(dir, strings.TrimSuffix(name, filepath.Ext(name))+testsSuffix))

		out = append(out, Rule{
			Lane:           lane,
			File:           path.Join("rules", lane, name),
			ID:             rule.ID,
			Title:          rule.Title,
			Level:          strings.ToLower(rule.Level),
			Status:         rule.Status,
			Description:    collapse(rule.Description),
			FiresWhen:      describeCondition(rule),
			FalsePositives: falsePositives(rule),
			Tags:           rule.Tags,
			References:     rule.References,
			TestCases:      total,
			FiringCases:    firing,
		})
	}
	return out, nil
}

type testCase struct {
	Name     string         `yaml:"name"`
	Expected bool           `yaml:"expected"`
	Event    map[string]any `yaml:"event"`
}

func countCases(path string) (total, firing int) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	var cases []testCase
	if err := yaml.Unmarshal(body, &cases); err != nil {
		return 0, 0
	}
	for _, c := range cases {
		total++
		if c.Expected {
			firing++
		}
	}
	return total, firing
}

// collapse turns a folded YAML description into one paragraph.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func matchingSearchNames(rule sigma.Rule, pattern string) []string {
	var names []string
	for name := range rule.Detection.Searches {
		if ok, _ := path.Match(pattern, name); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func writePreamble(b *strings.Builder, all []Rule) {
	fmt.Fprintf(b, `# Detection rules

**%d rules across %d log sources.**

> Generated from the rules tree by `+"`make docs`"+`. Do not edit by hand —
> `+"`TestRules_CatalogIsUpToDate`"+` fails if this file and the rules disagree.

## How to read an alert

An alert arrives as one `+"`detection.alert.v1`"+` message on the shared
`+"`detections-alerts`"+` queue, carrying the rule that fired, the record that
fired it, and where that record came from:

`+"```json"+`
{"schema_version":"detection.alert.v1","id":"det_…","alerted_at":"…",
 "log_source":"aws",
 "rule":{"id":"…","title":"…","level":"high","tags":[…],"file":"aws/….yml"},
 "provenance":{"bucket":"filtered-…","key":"aws/date=…/….ndjson.gz",
               "event_index":0,"sqs_message_id":"…"},
 "event":{…the record as Vector wrote it…},"event_sha256":"…"}
`+"```"+`

Three things worth knowing when triaging:

- **`+"`rule.id`"+` is the join key back to this page.** Find the rule below by
  its id to get the description, the false positives and the exact match
  condition.
- **`+"`id`"+` is content-derived**, from the rule id plus the object key and
  the record's index within it — never the clock. The same detection redelivered
  produces a byte-identical id, so duplicates are duplicates and consumers
  upsert on it.
- **`+"`provenance`"+` locates the original record**, so you can pull the
  surrounding events out of the filtered bucket for context.

## What these rules cannot do

Matching is **stateless and single-event**: each record is evaluated on its own.
Aggregations, `+"`timeframe`"+` and correlation rules are rejected when the
ruleset loads, rather than silently half-working.

So there are no brute-force, rate-spike or impossible-travel detections here,
and there cannot be until the engine keeps cross-event state. Anything of that
shape has to be expressed as a single record — usually by having the producer
compute the fact and emit it.

Wildcards also do not work in a value: `+"`*`"+` is matched literally. See
`+"`rules/README.md`"+`.

`, len(all), countLanes(all))
}

func countLanes(all []Rule) int {
	seen := map[string]bool{}
	for _, r := range all {
		seen[r.Lane] = true
	}
	return len(seen)
}

// falsePositives pulls the falsepositives block out of AdditionalFields.
//
// sigma-go has no struct field for it -- it is not part of the subset the
// evaluator needs -- but it is the single most useful thing on the page for
// somebody deciding whether an alert is worth waking up for, so it is worth
// digging out. YAML allows either a list or a bare string.
func falsePositives(rule sigma.Rule) []string {
	raw, ok := rule.AdditionalFields["falsepositives"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return []string{collapse(v)}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, collapse(s))
			}
		}
		return out
	}
	return nil
}

func writeSummary(b *strings.Builder, all []Rule) {
	levels := []string{"critical", "high", "medium", "low", "informational"}

	byLane := map[string]map[string]int{}
	laneTotals := map[string]int{}
	levelTotals := map[string]int{}
	for _, r := range all {
		if byLane[r.Lane] == nil {
			byLane[r.Lane] = map[string]int{}
		}
		byLane[r.Lane][r.Level]++
		laneTotals[r.Lane]++
		levelTotals[r.Level]++
	}

	lanes := make([]string, 0, len(byLane))
	for lane := range byLane {
		lanes = append(lanes, lane)
	}
	sort.Strings(lanes)

	b.WriteString("## Coverage\n\n| Log source |")
	for _, l := range levels {
		fmt.Fprintf(b, " %s %s |", levelBadge[l], l)
	}
	b.WriteString(" **Total** |\n|---|")
	for range levels {
		b.WriteString("---:|")
	}
	b.WriteString("---:|\n")

	for _, lane := range lanes {
		fmt.Fprintf(b, "| [`%s`](#%s) |", lane, lane)
		for _, l := range levels {
			writeCount(b, byLane[lane][l])
		}
		fmt.Fprintf(b, " **%d** |\n", laneTotals[lane])
	}

	b.WriteString("| **Total** |")
	for _, l := range levels {
		fmt.Fprintf(b, " **%d** |", levelTotals[l])
	}
	fmt.Fprintf(b, " **%d** |\n\n", len(all))
}

// writeCount renders a zero as a dash. A grid of zeroes reads as noise; a grid
// of dashes with a few numbers in it reads as a coverage map.
func writeCount(b *strings.Builder, n int) {
	if n == 0 {
		b.WriteString(" – |")
		return
	}
	fmt.Fprintf(b, " %d |", n)
}

func writeRules(b *strings.Builder, all []Rule) {
	var lane string
	for _, r := range all {
		if r.Lane != lane {
			lane = r.Lane
			fmt.Fprintf(b, "---\n\n## %s\n\n", lane)
		}
		writeRule(b, r)
	}
}

func writeRule(b *strings.Builder, r Rule) {
	badge := levelBadge[r.Level]
	if badge == "" {
		badge = "❔"
	}
	fmt.Fprintf(b, "### %s %s — %s\n\n", badge, r.Level, r.Title)

	// The id first, because it is what somebody arrives with: it is on the
	// alert, and it is the only stable handle back to this entry.
	fmt.Fprintf(b, "`%s` · [`%s`](../%s) · %s\n\n", r.ID, r.File, r.File, testsPhrase(r))

	if r.Status != "" && r.Status != "stable" {
		fmt.Fprintf(b, "> **Status: %s.**\n\n", r.Status)
	}
	if r.Description != "" {
		fmt.Fprintf(b, "%s\n\n", r.Description)
	}
	if r.FiresWhen != "" {
		fmt.Fprintf(b, "**Fires when** %s\n\n", r.FiresWhen)
	}
	if len(r.FalsePositives) > 0 {
		b.WriteString("**Likely false positives**\n\n")
		for _, fp := range r.FalsePositives {
			fmt.Fprintf(b, "- %s\n", fp)
		}
		b.WriteString("\n")
	}
	if len(r.Tags) > 0 {
		fmt.Fprintf(b, "**ATT&CK** %s\n\n", strings.Join(r.Tags, ", "))
	}
	for _, ref := range r.References {
		fmt.Fprintf(b, "- <%s>\n", ref)
	}
	if len(r.References) > 0 {
		b.WriteString("\n")
	}
}

// testsPhrase reports the sidecar coverage. A rule with no firing case cannot
// be distinguished from one that never matches, so the count is worth showing
// next to the rule rather than buried in CI.
func testsPhrase(r Rule) string {
	switch {
	case r.TestCases == 0:
		return "**no test cases**"
	case r.FiringCases == 0:
		return fmt.Sprintf("%d tests, **none firing**", r.TestCases)
	default:
		return fmt.Sprintf("%d tests (%d firing)", r.TestCases, r.FiringCases)
	}
}
