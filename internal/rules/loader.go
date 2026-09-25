package rules

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
)

// Store is the slice of S3 the loader needs. FSStore satisfies it over a
// directory, in which case bucket is ignored and prefix is a relative path.
type Store interface {
	List(ctx context.Context, bucket, prefix string) ([]string, error)
	Get(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// maxRuleBytes caps one rule file. A rule is a few kilobytes of YAML; the cap
// exists so that a wrong prefix pointing at a log object cannot be read into
// memory as a "rule".
const maxRuleBytes = 1 << 20

// LoadResult reports what a load produced, for the startup log.
type LoadResult struct {
	Set        *Set
	ConfigKeys []string
	RuleKeys   []string
}

// Load fetches and compiles the ruleset for one source.
//
// The store is either the tree baked into the image (FSStore) or an S3 bucket
// an installation points at to ship its own rules. With the bucket, a rule fix
// ships by restarting a task instead of rebuilding and redeploying, at the
// cost of a hard dependency for task start: an outage or an IAM regression
// means the task never becomes ready. That is the correct trade for a
// detection engine -- see Compile's ErrNoRules -- but it means the alarm must
// be on task-start failure and readiness, not on queue depth, which also
// rises during an ordinary traffic spike.
func Load(ctx context.Context, store Store, bucket, prefix, configFile string, log *slog.Logger) (LoadResult, error) {
	keys, err := store.List(ctx, bucket, prefix)
	if err != nil {
		return LoadResult{}, fmt.Errorf("listing %s: %w", location(bucket, prefix), err)
	}

	// Sorted so the digest, the startup log and any error are reproducible
	// across restarts regardless of listing order.
	sort.Strings(keys)

	var (
		result  LoadResult
		files   []File
		configs []sigma.Config
	)

	for _, key := range keys {
		ext := strings.ToLower(path.Ext(key))
		if ext != ".yml" && ext != ".yaml" {
			// Not silently ignored at debug level only: a file somebody meant
			// as a rule but named .txt would otherwise never be mentioned.
			log.Warn("skipping non-YAML object in the rules prefix", "key", key)
			continue
		}

		body, err := fetch(ctx, store, bucket, key)
		if err != nil {
			return LoadResult{}, err
		}

		if path.Base(key) == configFile {
			cfg, err := sigma.ParseConfig(body)
			if err != nil {
				return LoadResult{}, fmt.Errorf("parsing config %s: %w", key, err)
			}
			configs = append(configs, cfg)
			result.ConfigKeys = append(result.ConfigKeys, key)
			continue
		}

		files = append(files, File{Name: key, Data: body})
		result.RuleKeys = append(result.RuleKeys, key)
	}

	set, err := Compile(files, configs)
	if err != nil {
		return LoadResult{}, fmt.Errorf("compiling rules from %s: %w", location(bucket, prefix), err)
	}
	result.Set = set
	return result, nil
}

// location renders where the rules were looked for, for error messages.
func location(bucket, prefix string) string {
	if bucket == "" {
		return prefix
	}
	return "s3://" + bucket + "/" + prefix
}

func fetch(ctx context.Context, store Store, bucket, key string) ([]byte, error) {
	rc, err := store.Get(ctx, bucket, key)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", key, err)
	}
	defer rc.Close()

	body, err := io.ReadAll(io.LimitReader(rc, maxRuleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", key, err)
	}
	if len(body) > maxRuleBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes; is the rules prefix pointing at log data?",
			key, maxRuleBytes)
	}
	return body, nil
}

// LogLoaded writes one line per rule plus a summary.
//
// One line per rule is the record of what is actually running, and it is
// bounded by the ruleset size. The summary is what a human reads.
//
// The caller's logger is expected to already carry log_source, so this does
// not add it.
func (r LoadResult) LogLoaded(log *slog.Logger) {
	byLevel := map[string]int{}
	for _, m := range r.Set.All() {
		log.Info("rule loaded",
			"id", m.RuleID, "title", m.Title, "level", m.Level, "key", m.File)
		level := m.Level
		if level == "" {
			level = "unspecified"
		}
		byLevel[level]++
	}
	log.Info("ruleset loaded",
		"rules", r.Set.Len(),
		"configs", len(r.ConfigKeys),
		"by_level", byLevel)
}

// LevelCounts is the ruleset broken down by severity, for the gauge.
func (r LoadResult) LevelCounts() map[string]int {
	out := map[string]int{}
	for _, m := range r.Set.All() {
		level := m.Level
		if level == "" {
			level = "unspecified"
		}
		out[level]++
	}
	return out
}
