package rules

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// examplesDir is the subtree under the rules root that is never loaded: it
// holds org-specific templates with placeholder values (see rules/examples/).
// The image build strips it too; this is the second line so that a developer
// pointing ENGINE_RULES_DIR at a checkout gets the same ruleset the image has.
const examplesDir = "examples"

// FSStore is a Store over a directory, for the rules tree baked into the
// image. It speaks the same key language as the S3 store so Load does not
// know which it has: bucket is ignored and prefix is a relative path under
// Root, and List returns forward-slash keys relative to Root exactly as S3
// would return them relative to the bucket.
type FSStore struct {
	Root string
}

// List returns every regular file under Root/prefix, as slash-separated keys
// relative to Root, skipping the examples/ subtree. Order is unspecified,
// matching S3; Load sorts.
func (s FSStore) List(_ context.Context, _ string, prefix string) ([]string, error) {
	root, err := s.root()
	if err != nil {
		return nil, err
	}
	// A prefix ending in "/" means "everything below", as it does in S3. fs.WalkDir
	// wants a clean directory name, so the slash is dropped and the tree walked.
	// A prefix that does not name a directory (S3 would then match "aws/x"
	// against "aws/") lists nothing, which Load reports as no rules.
	dir := path.Clean(strings.TrimSuffix(prefix, "/"))
	if dir == "" {
		dir = "."
	}
	if !fs.ValidPath(dir) {
		return nil, fmt.Errorf("rules prefix %q does not stay under %s", prefix, s.Root)
	}
	if info, err := fs.Stat(root, dir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	} else if !info.IsDir() {
		return nil, nil
	}

	var keys []string
	err = fs.WalkDir(root, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == examplesDir || strings.HasPrefix(p, examplesDir+"/") {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		keys = append(keys, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s/%s: %w", s.Root, dir, err)
	}
	return keys, nil
}

// Get opens the file the key names.
func (s FSStore) Get(_ context.Context, _ string, key string) (io.ReadCloser, error) {
	root, err := s.root()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(key) {
		return nil, fmt.Errorf("rules key %q does not stay under %s", key, s.Root)
	}
	f, err := root.Open(key)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// root checks the directory exists up front so that a wrong ENGINE_RULES_DIR
// reads as "no such directory" rather than "zero rules".
func (s FSStore) root() (fs.FS, error) {
	info, err := os.Stat(s.Root)
	if err != nil {
		return nil, fmt.Errorf("rules dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules dir %s is not a directory", s.Root)
	}
	return os.DirFS(filepath.Clean(s.Root)), nil
}
