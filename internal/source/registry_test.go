package source_test

import (
	"strings"
	"testing"

	"github.com/samma-io/detection-engine/internal/source"
)

// detectionSources mirrors the lane list in the aws-siem detection-engine
// Terraform module (samma-io/aws-siem, docs/contracts/lane-names.md).
//
// It is duplicated here on purpose: that list is what creates the per-source
// SQS queues, and a lane with a queue but no registry entry would deploy an
// engine that starts, drains its queue and matches nothing. Terraform cannot
// check the Go side, so the contract is asserted from here. When you add a
// lane there, add it here and to the registry in the same change.
var detectionSources = []string{"aws", "gcp", "github", "workspace", "slack", "onepassword", "dns", "alb"}

func TestRegistry_HasAnEntryForEveryDetectionSource(t *testing.T) {
	for _, name := range detectionSources {
		if _, err := source.Lookup(name); err != nil {
			t.Errorf("terraform creates a queue for %q but the registry has no entry: %v", name, err)
		}
	}
	if got, want := len(source.Names()), len(detectionSources); got != want {
		t.Errorf("registry has %d sources, terraform has %d: %v vs %v",
			got, want, source.Names(), detectionSources)
	}
}

func TestLookup_UnknownSourceNamesTheValidOnes(t *testing.T) {
	_, err := source.Lookup("splunk")
	if err == nil {
		t.Fatal("expected an error for an unknown source")
	}
	// The operator reading this is looking at a task that will not start.
	for _, name := range detectionSources {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should list %q as valid, got: %v", name, err)
		}
	}
}

func TestLookup_EmptySourceIsAnError(t *testing.T) {
	if _, err := source.Lookup("  "); err == nil {
		t.Fatal("an unset log source must not resolve to a default")
	}
}

func TestLookup_IsCaseAndSpaceInsensitive(t *testing.T) {
	s, err := source.Lookup("  AWS ")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if s.Name != "aws" {
		t.Errorf("Name = %q, want %q", s.Name, "aws")
	}
}
