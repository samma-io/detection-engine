package rulecheck_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samma-io/detection-engine/internal/rulesdoc"
)

// TestRules_CatalogIsUpToDate keeps docs/RULES.md honest.
//
// The catalogue is what somebody reads when an alert wakes them up, which is
// the worst possible moment to be reading a description of a rule as it was
// three months ago. A generated document with no gate is a document that is
// wrong and looks authoritative -- strictly worse than not having one, because
// nobody thinks to check it against the rule.
//
// So the generated output is compared against the committed file, and a rule
// change that does not run `make docs` does not go green.
func TestRules_CatalogIsUpToDate(t *testing.T) {
	root := repoRoot(t)

	want, err := rulesdoc.Render(filepath.Join(root, "rules"))
	if err != nil {
		t.Fatalf("rendering the catalogue: %v", err)
	}

	path := filepath.Join(root, rulesdoc.OutputPath)
	got, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("%s does not exist; run `make docs`", rulesdoc.OutputPath)
		}
		t.Fatal(err)
	}

	if string(got) != want {
		t.Errorf("%s is out of date -- run `make docs` and commit the result.\n"+
			"(committed %d bytes, rules tree renders %d)",
			rulesdoc.OutputPath, len(got), len(want))
	}
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd))
}
