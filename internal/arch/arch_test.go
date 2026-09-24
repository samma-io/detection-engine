// Package arch holds tests about the shape of the codebase rather than its
// behaviour.
package arch_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const module = "github.com/samma-io/detection-engine"

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd)) // internal/arch -> repo root
}

func goFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "bin" || strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPackages_DoNotImportTheAWSSDK keeps the SDK confined to internal/awsadapt
// and cmd/.
//
// It is worth more than the layout choice it enforces: the moment a business
// package imports the SDK, some unit test starts needing credentials, and the
// next person reaches for a live AWS call instead of a fake. Every interface in
// this repo exists so that the pure packages can be tested without a network.
func TestPackages_DoNotImportTheAWSSDK(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{
		filepath.Join(root, "internal", "awsadapt"): true,
		filepath.Join(root, "cmd", "engine"):        true,
		// This package talks *about* the SDK, so its own source mentions it.
		filepath.Join(root, "internal", "arch"): true,
	}

	for _, file := range goFiles(t, filepath.Join(root, "internal")) {
		if allowed[filepath.Dir(file)] {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "aws-sdk-go-v2") {
			rel, _ := filepath.Rel(root, file)
			t.Errorf("%s imports the AWS SDK; it belongs behind an interface in internal/awsadapt", rel)
		}
	}
}

var declRe = regexp.MustCompile(`(?m)^\t([A-Z][A-Za-z0-9]*)\s*=\s*prometheus\.New`)

// TestMetrics_EveryCollectorHasAnIncrementSite is the guard against dead
// metrics.
//
// A sibling service in this workspace registered five collectors it never
// touched. They rendered as flat zero lines on the dashboard, and a flat zero
// is indistinguishable from a healthy quiet period -- which is exactly the
// failure a detection engine cannot afford. A metric with no increment site is
// worse than no metric at all.
func TestMetrics_EveryCollectorHasAnIncrementSite(t *testing.T) {
	root := repoRoot(t)
	metricsFile := filepath.Join(root, "internal", "metrics", "metrics.go")

	body, err := os.ReadFile(metricsFile)
	if err != nil {
		t.Fatal(err)
	}
	declared := declRe.FindAllStringSubmatch(string(body), -1)
	if len(declared) == 0 {
		t.Fatal("found no collector declarations; has the metrics package moved?")
	}

	// Gather every reference outside the metrics package itself.
	var refs strings.Builder
	for _, file := range append(goFiles(t, filepath.Join(root, "internal")), goFiles(t, filepath.Join(root, "cmd"))...) {
		if filepath.Base(filepath.Dir(file)) == "metrics" {
			continue
		}
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		refs.Write(b)
	}
	all := refs.String()

	for _, m := range declared {
		name := m[1]
		if !strings.Contains(all, "metrics."+name) {
			t.Errorf("detection metric %q is declared but never used: either increment it "+
				"or delete it, because a flat zero line reads as \"nothing is wrong\"", name)
		}
	}
}
