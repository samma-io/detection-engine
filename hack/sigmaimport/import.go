package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	"gopkg.in/yaml.v3"

	"github.com/samma-io/detection-engine/internal/rules"
)

// fixture is the TrailAlerts test-fixture shape: raw CloudTrail records split
// by whether the rule should match them.
type fixture struct {
	ShouldMatch    []map[string]any `json:"should_match"`
	ShouldNotMatch []map[string]any `json:"should_not_match"`
}

// indexFixtures maps a rule id to the fixture file for it. The fixtures sit
// beside their rule, so the id comes from the rule, not the fixture.
func indexFixtures(dir string) (map[string]string, error) {
	out := map[string]string{}
	paths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		r, err := sigma.ParseRule(body)
		if err != nil || r.ID == "" {
			continue
		}
		f := strings.TrimSuffix(p, ".yml") + "_tests.json"
		if _, err := os.Stat(f); err == nil {
			out[r.ID] = f
		}
	}
	return out, nil
}

// globInValue finds the wildcards this engine matches literally. Mirrors
// TestRules_NoGlobsInDetectionValues; a rule carrying one compiles, loads and
// is wrong forever, so it is rejected at import rather than shipped.
var comparatorTakesPattern = map[string]bool{"re": true, "base64": true}

func globInValue(r sigma.Rule) string {
	for name, search := range r.Detection.Searches {
		for _, em := range search.EventMatchers {
			for _, fm := range em {
				skip := false
				for _, m := range fm.Modifiers {
					if comparatorTakesPattern[m] {
						skip = true
					}
				}
				if skip {
					continue
				}
				for _, v := range fm.Values {
					if s, ok := v.(string); ok && strings.ContainsAny(s, "*?") {
						return fmt.Sprintf("search %q field %q value %q", name, fm.Field, s)
					}
				}
			}
		}
	}
	return ""
}

// consider runs every gate against one upstream rule.
func consider(path string, cfg []sigma.Config, fixtures, existing, declined map[string]string, samples *sampleSet, skipExisting bool) decision {
	d := decision{File: filepath.Base(path), SrcPath: path}

	body, err := os.ReadFile(path)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	r, err := sigma.ParseRule(body)
	if err != nil {
		d.Reason = "does not parse: " + err.Error()
		return d
	}
	d.ID, d.Title, d.Level = r.ID, r.Title, strings.ToLower(r.Level)

	// A declined rule is a decision already made. Absence from the tree is
	// exactly what "new" looks like, so without this a re-import quietly
	// reverses every curation call anyone has ever made.
	if why, ok := declined[r.ID]; ok {
		d.Reason = "declined: " + firstLine(why)
		return d
	}

	if skipExisting {
		if where, dup := existing[r.ID]; dup {
			d.Reason = "already present as " + where
			return d
		}
	}

	// Gate A: the engine's own admission path. Catches aggregations,
	// timeframe, correlation, keywords, unimplemented modifiers, placeholders.
	if _, err := rules.Compile([]rules.File{{Name: d.File, Data: body}}, cfg); err != nil {
		d.Reason = compactErr(err)
		return d
	}

	// Gate B: wildcards in a value. Not caught by Gate A -- it is a pure
	// silent non-match.
	if g := globInValue(r); g != "" {
		d.Reason = "wildcard in a value (" + g + "); sigma-go matches values literally"
		return d
	}

	// Gate C: a fixture, or nothing worth importing. A rule with no realistic
	// event to prove it fires is a rule we cannot honestly claim coverage for,
	// and a generated stub derived from the rule proves only that the rule
	// matches itself.
	if f, ok := fixtures[r.ID]; ok {
		d.Fixture = f
		d.Accepted = true
		return d
	}

	// No upstream fixture. Fall back to evidence from real traffic: if the rule
	// fires on records this estate actually produced, those records are a
	// better sidecar than anything anyone would write by hand.
	if samples == nil {
		d.Reason = "no upstream fixture and no -samples given"
		return d
	}
	ev, err := samples.test(d.File, body, cfg)
	if err != nil {
		d.Reason = "evaluating against samples: " + compactErr(err)
		return d
	}
	if len(ev.Matched) == 0 {
		// Separate "cannot fire here" from "has not fired yet". Conflating them
		// would hide a taxonomy mismatch behind a quiet week.
		if missing := missingFields(r, samples.knownFields(), cfg); len(missing) > 0 {
			d.Reason = fmt.Sprintf("FIELD ABSENT: %s not seen in %d sampled %s records -- either the rule targets events that did not occur in this window, or the field name is wrong for this lane. Widen the sample before concluding.",
				joinShort(missing, 3), ev.Total, samples.Lane)
			d.CannotFire = true
			return d
		}
		d.Reason = fmt.Sprintf("can fire but has not: fields present, no matching value in %d sampled %s records",
			ev.Total, samples.Lane)
		d.CanFireUnseen = true
		return d
	}
	if ev.LostToScrub > 0 && len(ev.Matched) == 0 {
		d.Reason = fmt.Sprintf("matched %d records but only via identifiers that scrubbing removes", ev.LostToScrub)
		return d
	}
	d.Evidence = ev
	d.Accepted = true
	return d
}

func compactErr(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", "; ")
	if i := strings.Index(s, ": "); i > 0 && len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// write emits the rule with a provenance header and a sidecar built from the
// upstream fixture.
//
// The upstream id is kept. rulecheck enforces global id uniqueness and the
// alert id is derived from it, so ids must be stable forever -- and keeping
// upstream's makes a re-import a diff rather than a duplicate, and keeps the
// join back to the upstream rule checkable.
func write(d *decision, laneDir, sigmaRef, fixtRef string) error {
	body, err := os.ReadFile(d.SrcPath)
	if err != nil {
		return err
	}

	lane := filepath.Base(laneDir)

	var (
		sidecar []byte
		n       int
	)
	if d.Fixture != "" {
		raw, err := os.ReadFile(d.Fixture)
		if err != nil {
			return err
		}
		var fx fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			return fmt.Errorf("%s: %w", d.Fixture, err)
		}
		sidecar, n, err = buildSidecar(fx, lane, d.File)
		if err != nil {
			return fmt.Errorf("%s: %w", d.File, err)
		}
	} else {
		var err error
		sidecar, n, err = sidecarFromEvidence(d.Evidence, lane, d.File)
		if err != nil {
			return fmt.Errorf("%s: %w", d.File, err)
		}
	}
	d.Cases = n

	name := nonName.ReplaceAllString(strings.ToLower(strings.TrimSuffix(d.File, ".yml")), "_")
	name = strings.TrimPrefix(name, "aws_")

	header := fmt.Sprintf(`# Imported by hack/sigmaimport -- do not hand-edit without recording why.
#   upstream:  SigmaHQ %s
#   ref:       %s
#   sidecar:   %s
#   licence:   SigmaHQ DRL-1.1%s
`, d.File, orNone(sigmaRef), sidecarSource(d, fixtRef), fixtureLicence(d))

	if err := os.WriteFile(filepath.Join(laneDir, name+".yml"), append([]byte(header), body...), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(laneDir, name+".tests.yml"), sidecar, 0o644)
}

func orNone(s string) string {
	if s == "" {
		return "(unrecorded)"
	}
	return s
}

// buildSidecar turns a TrailAlerts fixture into our .tests.yml shape.
//
// Every event gains source: <lane>, because Vector stamps one on every record
// and TestRules_TestEventsCarryTheLaneEnvelope requires it. Nothing else is
// altered: the value of these fixtures is that they are real records.
func buildSidecar(fx fixture, lane, ruleFile string) ([]byte, int, error) {
	type testCase struct {
		Name     string         `yaml:"name"`
		Expected bool           `yaml:"expected"`
		Event    map[string]any `yaml:"event"`
	}
	var cases []testCase
	for i, e := range fx.ShouldMatch {
		e["source"] = lane
		cases = append(cases, testCase{
			Name:     fmt.Sprintf("upstream fixture: should match (%d)", i+1),
			Expected: true,
			Event:    e,
		})
	}
	for i, e := range fx.ShouldNotMatch {
		e["source"] = lane
		cases = append(cases, testCase{
			Name:     fmt.Sprintf("upstream fixture: should not match (%d)", i+1),
			Expected: false,
			Event:    e,
		})
	}
	if len(cases) == 0 {
		return nil, 0, fmt.Errorf("fixture has no cases")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by hack/sigmaimport from the TrailAlerts fixture for this\n")
	fmt.Fprintf(&b, "# rule. These are real CloudTrail record shapes, which is the point: a\n")
	fmt.Fprintf(&b, "# test event written from the rule proves only that the rule matches\n")
	fmt.Fprintf(&b, "# itself. Only `source` was added, because Vector stamps one on every\n")
	fmt.Fprintf(&b, "# record.\n")
	out, err := yaml.Marshal(cases)
	if err != nil {
		return nil, 0, err
	}
	b.Write(out)
	return []byte(b.String()), len(cases), nil
}

func report(ds []decision, applied, verbose bool) {
	var ok, rejected int
	byReason := map[string]int{}
	for _, d := range ds {
		if d.Accepted {
			ok++
			continue
		}
		rejected++
		key := d.Reason
		if i := strings.Index(key, "("); i > 0 {
			key = key[:i]
		}
		if len(key) > 70 {
			key = key[:70]
		}
		byReason[key]++
	}

	fmt.Printf("\n%d considered, %d accepted, %d rejected\n\n", len(ds), ok, rejected)
	if !applied && ok > 0 {
		fmt.Printf("(dry run -- nothing written; pass -apply)\n\n")
	}

	if verbose {
		for _, d := range ds {
			status := "reject"
			if d.Accepted {
				status = "ACCEPT"
			}
			fmt.Printf("  %-6s %-52s %s\n", status, d.File, d.Reason)
		}
		fmt.Println()
	}

	fmt.Println("rejected, by reason:")
	keys := make([]string, 0, len(byReason))
	for k := range byReason {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return byReason[keys[i]] > byReason[keys[j]] })
	for _, k := range keys {
		fmt.Printf("  %3d  %s\n", byReason[k], k)
	}
}

// declinedEntry is one line of hack/sigmaimport/declined.yml.
type declinedEntry struct {
	ID     string `yaml:"id"`
	Rule   string `yaml:"rule"`
	Reason string `yaml:"reason"`
}

func loadDeclined(path string) (map[string]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var entries []declinedEntry
	if err := yaml.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("%s: entry %s has no reason", path, e.ID)
		}
		out[e.ID] = e.Reason
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// sidecarSource records where the test cases came from, because "real traffic"
// and "an upstream fixture" are different claims about a rule.
func sidecarSource(d *decision, fixtRef string) string {
	if d.Fixture != "" {
		return fmt.Sprintf("TrailAlerts %s @ %s", filepath.Base(d.Fixture), orNone(fixtRef))
	}
	return fmt.Sprintf("derived from %d real records in the filtered bucket", d.Evidence.Total)
}

func fixtureLicence(d *decision) string {
	if d.Fixture != "" {
		return "; fixture Apache-2.0"
	}
	return ""
}
