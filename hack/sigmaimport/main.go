// Command sigmaimport brings upstream Sigma rules into rules/<lane>/.
//
// It exists because hand-writing rules does not scale: the expensive part is
// never the detection logic, it is a realistic test event proving the rule can
// fire against what the source actually emits. Upstream SigmaHQ supplies the
// rules; TrailAlerts supplies fixtures of real CloudTrail records keyed by the
// same rule ids, so for most rules both halves can be had mechanically.
//
// Admission is decided by internal/rules.Compile -- the engine's own predicate,
// not a copy of it. A reimplementation would drift on the first sigma-go bump,
// and drift silently in the direction that matters.
//
//	go run ./hack/sigmaimport -sigma <dir> -fixtures <dir> -lane aws [-apply]
//
// Without -apply it reports and writes nothing.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
)

type decision struct {
	File          string
	SrcPath       string
	ID            string
	Title         string
	Level         string
	Accepted      bool
	Reason        string
	Fixture       string    // path to the TrailAlerts fixture, if one matched
	Evidence      *evidence // matches against real sampled records, when no fixture exists
	CannotFire    bool      // a field it matches on is absent from our logs entirely
	CanFireUnseen bool      // fields present, value simply has not occurred yet
	Cases         int
}

func main() {
	var (
		sigmaDir  = flag.String("sigma", "", "directory of upstream Sigma rule .yml files")
		fixtures  = flag.String("fixtures", "", "directory of TrailAlerts *_tests.json fixtures (optional)")
		lane      = flag.String("lane", "aws", "target lane under rules/")
		root      = flag.String("root", ".", "repository root")
		apply     = flag.Bool("apply", false, "write the accepted rules; without this nothing is written")
		sigmaRef  = flag.String("sigma-ref", "", "upstream SigmaHQ commit sha, recorded in each rule header")
		fixtRef   = flag.String("fixtures-ref", "", "upstream TrailAlerts commit sha")
		skipExist = flag.Bool("skip-existing", true, "skip rules whose id is already present in the tree")
		verbose   = flag.Bool("verbose", false, "print a line per rule instead of a grouped summary")
		samples   = flag.String("samples", "", "NDJSON of real records for this lane; used to derive sidecars when no upstream fixture exists")
	)
	flag.Parse()

	if *sigmaDir == "" {
		fmt.Fprintln(os.Stderr, "-sigma is required")
		os.Exit(2)
	}

	laneDir := filepath.Join(*root, "rules", *lane)
	cfg, err := laneConfig(laneDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading the lane config: %v\n", err)
		os.Exit(1)
	}

	existing, err := existingIDs(filepath.Join(*root, "rules"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanning existing rules: %v\n", err)
		os.Exit(1)
	}

	declined, err := loadDeclined(filepath.Join("hack", "sigmaimport", "declined.yml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading the declined list: %v\n", err)
		os.Exit(1)
	}

	fixtureByID := map[string]string{}
	if *fixtures != "" {
		fixtureByID, err = indexFixtures(*fixtures)
		if err != nil {
			fmt.Fprintf(os.Stderr, "indexing fixtures: %v\n", err)
			os.Exit(1)
		}
	}

	var sampleSet_ *sampleSet
	if *samples != "" {
		sampleSet_, err = loadSamples(*samples, *lane)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading samples: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("loaded %d real %s records as evidence\n", len(sampleSet_.Records), *lane)
	}

	paths, err := filepath.Glob(filepath.Join(*sigmaDir, "*.yml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	sort.Strings(paths)

	var decisions []decision
	for _, p := range paths {
		decisions = append(decisions, consider(p, cfg, fixtureByID, existing, declined, sampleSet_, *skipExist))
	}

	if *apply {
		for i := range decisions {
			if !decisions[i].Accepted {
				continue
			}
			if err := write(&decisions[i], laneDir, *sigmaRef, *fixtRef); err != nil {
				fmt.Fprintf(os.Stderr, "writing %s: %v\n", decisions[i].File, err)
				os.Exit(1)
			}
		}
	}

	report(decisions, *apply, *verbose)
}

// laneConfig loads the lane's sigma-config so admission runs against exactly
// what the engine will use, fieldmappings included.
func laneConfig(dir string) ([]sigma.Config, error) {
	body, err := os.ReadFile(filepath.Join(dir, "sigma-config.yml"))
	if err != nil {
		return nil, err
	}
	c, err := sigma.ParseConfig(body)
	if err != nil {
		return nil, err
	}
	return []sigma.Config{c}, nil
}

// existingIDs collects every rule id already in the tree. Ids must be unique
// across every lane -- the alert id is derived from them -- so a re-import must
// not reintroduce one.
func existingIDs(rulesRoot string) (map[string]string, error) {
	out := map[string]string{}
	lanes, err := os.ReadDir(rulesRoot)
	if err != nil {
		return nil, err
	}
	for _, l := range lanes {
		if !l.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(rulesRoot, l.Name(), "*.yml"))
		for _, f := range files {
			if strings.HasSuffix(f, ".tests.yml") || strings.HasSuffix(f, "sigma-config.yml") {
				continue
			}
			body, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if r, err := sigma.ParseRule(body); err == nil && r.ID != "" {
				out[r.ID] = filepath.Base(f)
			}
		}
	}
	return out, nil
}
