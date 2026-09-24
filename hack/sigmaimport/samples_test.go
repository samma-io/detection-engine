package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
	"gopkg.in/yaml.v3"
)

const probeRule = `title: Probe
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
description: d
level: medium
logsource: {product: github, service: audit}
detection:
  selection:
    action: team.update_repository_permission
  condition: selection
`

func writeSamples(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.ndjson")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A sidecar derived from real traffic is only worth having if the positives are
// records that genuinely matched and the negatives genuinely did not. Both
// halves are asserted, because a generator that quietly emitted the same record
// as both would still produce a passing sidecar.
func TestSampleEvidence_SplitsMatchedFromUnmatched(t *testing.T) {
	path := writeSamples(t,
		`{"action":"team.update_repository_permission","repo":"example-org/x"}`,
		`{"action":"api.request","route":"/graphql"}`,
		`{"action":"repo.download_zip"}`,
	)
	s, err := loadSamples(path, "github")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Records) != 3 {
		t.Fatalf("loaded %d records, want 3", len(s.Records))
	}
	// loadSamples must stamp source, because every rule and guard expects it.
	if s.Records[0]["source"] != "github" {
		t.Errorf("source not stamped: %v", s.Records[0]["source"])
	}

	ev, err := s.test("probe.yml", []byte(probeRule), []sigma.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Matched) != 1 {
		t.Errorf("matched %d, want 1", len(ev.Matched))
	}
	if len(ev.NotMatched) != 2 {
		t.Errorf("not-matched %d, want 2", len(ev.NotMatched))
	}

	body, n, err := sidecarFromEvidence(ev, "github", "probe.yml")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("%d cases, want 3", n)
	}
	out := string(body)
	if !strings.Contains(out, "expected: true") || !strings.Contains(out, "expected: false") {
		t.Errorf("sidecar lacks both polarities:\n%s", out)
	}
	if !strings.Contains(out, "REAL records") {
		t.Errorf("sidecar does not record that it came from real traffic")
	}
}

// A rule that matches nothing must NOT produce a sidecar. Emitting one would
// assert coverage that has not been demonstrated -- the exact thing the
// .tests.yml gate exists to prevent.
func TestSampleEvidence_NoMatchProducesNoSidecar(t *testing.T) {
	path := writeSamples(t, `{"action":"api.request"}`)
	s, err := loadSamples(path, "github")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := s.test("probe.yml", []byte(probeRule), []sigma.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Matched) != 0 {
		t.Fatalf("expected no matches, got %d", len(ev.Matched))
	}
	if _, _, err := sidecarFromEvidence(ev, "github", "probe.yml"); err == nil {
		t.Fatal("sidecarFromEvidence succeeded with no matched records")
	}
}

// A malformed line must not abort an import of thousands of good records.
func TestLoadSamples_SkipsUnparseableLines(t *testing.T) {
	path := writeSamples(t, `{"action":"a"}`, `not json at all`, `{"action":"b"}`)
	s, err := loadSamples(path, "github")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Records) != 2 {
		t.Errorf("loaded %d records, want 2 (the bad line skipped)", len(s.Records))
	}
}

// Scrubbing is the difference between a useful fixture and a PII leak
// committed to git forever, so it is tested on the shapes that actually appear
// in these logs rather than on contrived strings.
func TestScrub_RemovesIdentifiersAndKeepsShape(t *testing.T) {
	in := map[string]any{
		"actor":              "some.person",
		"actor_email":        "jane.doe@example.net",
		"actor_ip":           "198.51.100.23",
		"internal_ip":        "10.1.55.67",
		"recipientAccountId": "111111111111",
		"hashed_token":       "ExampleHashedToken0000000000000000000000000=",
		"userIdentity": map[string]any{
			"arn":         "arn:aws:sts::111111111111:assumed-role/ExampleRole/jane.doe@example.net",
			"principalId": "AROA4EXAMPLEREALVALUE",
		},
		"cidr":      "0.0.0.0/0",
		"eventName": "PutBucketPolicy",
		"count":     float64(3),
	}
	out := scrubRecord(in)
	flat := strings.ToLower(fmtAny(out))

	for _, leak := range []string{"example.net", "jane.doe", "198.51.100.23", "111111111111", "examplehashedtoken"} {
		if strings.Contains(flat, leak) {
			t.Errorf("scrubbed record still contains %q:\n%s", leak, flat)
		}
	}
	// Shape and security-relevant values must survive.
	if out["eventName"] != "PutBucketPolicy" {
		t.Errorf("eventName altered: %v", out["eventName"])
	}
	if out["cidr"] != "0.0.0.0/0" {
		t.Errorf("0.0.0.0/0 must be preserved, it is what rules match on: %v", out["cidr"])
	}
	if out["internal_ip"] != "10.1.55.67" {
		t.Errorf("RFC1918 address should be kept, it describes topology not a person: %v", out["internal_ip"])
	}
	if out["count"] != float64(3) {
		t.Errorf("non-string value altered: %v", out["count"])
	}
	ui, _ := out["userIdentity"].(map[string]any)
	if ui == nil {
		t.Fatal("nested object lost")
	}
	if arn, _ := ui["arn"].(string); !strings.HasPrefix(arn, "arn:aws:sts::") {
		t.Errorf("ARN shape not preserved: %v", ui["arn"])
	}
}

func fmtAny(v any) string {
	b, _ := yaml.Marshal(v)
	return string(b)
}
