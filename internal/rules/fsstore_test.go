package rules_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/samma-io/detection-engine/internal/rules"
)

// tree writes files under a temp root and returns the root.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func list(t *testing.T, root, prefix string) []string {
	t.Helper()
	keys, err := rules.FSStore{Root: root}.List(context.Background(), "ignored", prefix)
	if err != nil {
		t.Fatalf("List(%q): %v", prefix, err)
	}
	sort.Strings(keys)
	return keys
}

func TestFSStore_ListReturnsSlashKeysUnderThePrefixOnly(t *testing.T) {
	root := tree(t, map[string]string{
		"aws/sigma-config.yml":  "title: aws\n",
		"aws/stop_logging.yml":  stopLogging,
		"aws/nested/deeper.yml": stopLogging,
		"github/other.yml":      stopLogging,
		"README.md":             "not a rule\n",
	})
	got := list(t, root, "aws/")
	want := []string{"aws/nested/deeper.yml", "aws/sigma-config.yml", "aws/stop_logging.yml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List(aws/) = %v, want %v", got, want)
	}
}

func TestFSStore_ListWithEmptyPrefixWalksTheWholeTree(t *testing.T) {
	root := tree(t, map[string]string{
		"aws/a.yml":    "",
		"github/b.yml": "",
	})
	got := list(t, root, "")
	want := []string{"aws/a.yml", "github/b.yml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List(\"\") = %v, want %v", got, want)
	}
}

func TestFSStore_ExamplesSubtreeIsSkipped(t *testing.T) {
	// rules/examples/ holds placeholder templates; the image strips it, and
	// a checkout pointed at directly must behave the same.
	root := tree(t, map[string]string{
		"aws/a.yml":                         "",
		"examples/org-specific/aws/x.yml":   "",
		"examples/README.md":                "",
		"aws/examples/still_a_rule_dir.yml": "", // only the top-level examples/ is special
	})
	if got, want := list(t, root, ""), []string{"aws/a.yml", "aws/examples/still_a_rule_dir.yml"}; !reflect.DeepEqual(got, want) {
		t.Errorf("List(\"\") = %v, want %v", got, want)
	}
	if got := list(t, root, "examples/"); len(got) != 0 {
		t.Errorf("List(examples/) = %v, want nothing", got)
	}
}

func TestFSStore_MissingPrefixListsNothing(t *testing.T) {
	// Mirrors S3: a prefix with no objects is an empty listing, and Load
	// turns that into ErrNoRules.
	root := tree(t, map[string]string{"aws/a.yml": ""})
	if got := list(t, root, "dns/"); len(got) != 0 {
		t.Errorf("List(dns/) = %v, want nothing", got)
	}
}

func TestFSStore_MissingRootIsAnError(t *testing.T) {
	// Unlike a missing prefix, a missing root is a wrong ENGINE_RULES_DIR and
	// must say so rather than report zero rules.
	_, err := rules.FSStore{Root: filepath.Join(t.TempDir(), "nope")}.List(context.Background(), "", "aws/")
	if err == nil {
		t.Fatal("expected an error for a missing rules dir")
	}
}

func TestFSStore_PrefixCannotEscapeTheRoot(t *testing.T) {
	root := tree(t, map[string]string{"aws/a.yml": ""})
	s := rules.FSStore{Root: root}
	if _, err := s.List(context.Background(), "", "../"); err == nil {
		t.Error("List(../) must not escape the root")
	}
	if _, err := s.Get(context.Background(), "", "../etc/passwd"); err == nil {
		t.Error("Get(../etc/passwd) must not escape the root")
	}
}

func TestFSStore_GetReadsTheFile(t *testing.T) {
	root := tree(t, map[string]string{"aws/a.yml": "title: a\n"})
	rc, err := rules.FSStore{Root: root}.Get(context.Background(), "", "aws/a.yml")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "title: a\n" {
		t.Errorf("body = %q", body)
	}
}

func TestLoad_WorksOverAnFSStore(t *testing.T) {
	// The end-to-end: the same Load that serves S3 compiles a directory tree
	// with bucket "" and the lane prefix.
	root := tree(t, map[string]string{
		"aws/sigma-config.yml": "title: aws\nfieldmappings: {}\n",
		"aws/stop_logging.yml": stopLogging,
		"github/other.yml":     stopLogging,
	})
	res, err := rules.Load(context.Background(), rules.FSStore{Root: root}, "", "aws/", "sigma-config.yml", quiet())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Set.Len() != 1 {
		t.Errorf("rules = %d, want 1", res.Set.Len())
	}
	if len(res.ConfigKeys) != 1 || res.ConfigKeys[0] != "aws/sigma-config.yml" {
		t.Errorf("ConfigKeys = %v", res.ConfigKeys)
	}
}
