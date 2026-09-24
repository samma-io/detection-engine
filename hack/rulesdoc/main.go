// Command rulesdoc regenerates docs/RULES.md from the committed rules tree.
//
// Run it with `make docs`. TestRules_CatalogIsUpToDate fails if the committed
// file and the rules disagree, so this is not optional housekeeping -- a rule
// PR that skips it does not go green.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samma-io/detection-engine/internal/rulesdoc"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "exit non-zero if the committed file is out of date, and write nothing")
	flag.Parse()

	out, err := rulesdoc.Render(filepath.Join(*root, "rules"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendering the catalogue: %v\n", err)
		os.Exit(1)
	}

	target := filepath.Join(*root, rulesdoc.OutputPath)

	if *check {
		current, err := os.ReadFile(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %v\n", target, err)
			os.Exit(1)
		}
		if string(current) != out {
			fmt.Fprintf(os.Stderr, "%s is out of date; run `make docs`\n", rulesdoc.OutputPath)
			os.Exit(1)
		}
		fmt.Printf("%s is up to date\n", rulesdoc.OutputPath)
		return
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(target, []byte(out), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", target, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", rulesdoc.OutputPath)
}
