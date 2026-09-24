// Package rules loads Sigma rules and evaluates events against them.
package rules

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/bradleyjkemp/sigma-go/evaluator/modifiers"
)

// errAggregationUnsupported is returned by the stub aggregation
// implementations below.
//
// supported() rejects aggregation rules at load time, so these should be
// unreachable -- which is exactly why they are installed. sigma-go calls
// rule.count / rule.sum / rule.average directly without a nil check, so an
// aggregation rule that slipped past admission would panic on every matching
// event and take the task down. Verified against v0.6.6: evaluating such a
// rule with no implementations panics with a nil pointer dereference.
// Unreachable and returning an error is a logged rule error; unreachable and
// nil is a crash loop.
var errAggregationUnsupported = errors.New("aggregation rules are not supported")

// aggregationStubs are passed to every evaluator as defence in depth.
func aggregationStubs() []evaluator.Option {
	return []evaluator.Option{
		evaluator.CountImplementation(func(context.Context, evaluator.GroupedByValues) (float64, error) {
			return 0, errAggregationUnsupported
		}),
		evaluator.SumImplementation(func(context.Context, evaluator.GroupedByValues, float64) (float64, error) {
			return 0, errAggregationUnsupported
		}),
		evaluator.AverageImplementation(func(context.Context, evaluator.GroupedByValues, float64) (float64, error) {
			return 0, errAggregationUnsupported
		}),
	}
}

// File is one rule as read from the rules bucket.
type File struct {
	// Name is the object key's base name, used in errors and as the rule
	// identity when the rule itself carries no id.
	Name string
	Data []byte
}

// Match describes a rule that fired. It is everything the alert needs from the
// rule side, extracted at compile time so evaluation allocates nothing extra.
type Match struct {
	RuleID      string   `json:"id"`
	Title       string   `json:"title"`
	Level       string   `json:"level,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	File        string   `json:"file"`
}

type compiled struct {
	meta      Match
	evaluator *evaluator.RuleEvaluator
}

// Set is an immutable, compiled ruleset.
//
// Nothing mutates it after Compile returns, which is what lets every worker
// goroutine share one Set without a lock.
type Set struct {
	rules []compiled
}

// ErrNoRules reports an empty ruleset.
//
// This is the worst failure this service has, and it is deliberately a hard
// error. An engine with no rules starts cleanly, drains its queue, matches
// nothing and deletes every message. Queue depth goes *down*, CPU looks
// normal, no log line is alarming, and the only symptom is an absence of
// alerts -- which is indistinguishable from a quiet week.
var ErrNoRules = errors.New("no rules loaded")

// Compile parses and compiles every rule against the shared configs.
//
// Any rule that fails is fatal, and every failure is reported together. A rule
// that does not compile is a detection that silently does not exist, so
// starting with the survivors would be worse than not starting: the operator
// would have no reason to look.
func Compile(files []File, configs []sigma.Config) (*Set, error) {
	if len(files) == 0 {
		return nil, ErrNoRules
	}

	// Sorted so the startup log, and any error listing rules, is stable
	// across deploys and diffable.
	sorted := make([]File, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	set := &Set{rules: make([]compiled, 0, len(sorted))}
	var problems []string

	for _, f := range sorted {
		rule, err := sigma.ParseRule(f.Data)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}
		if err := supported(rule); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}

		set.rules = append(set.rules, compiled{
			meta: Match{
				RuleID:      identity(rule, f.Name),
				Title:       rule.Title,
				Level:       strings.ToLower(rule.Level),
				Description: rule.Description,
				Tags:        rule.Tags,
				References:  rule.References,
				File:        f.Name,
			},
			evaluator: evaluator.ForRule(rule, append(aggregationStubs(),
				evaluator.WithConfig(configs...))...),
		})
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("%d of %d rules did not compile:\n  - %s",
			len(problems), len(sorted), strings.Join(problems, "\n  - "))
	}
	if len(set.rules) == 0 {
		return nil, ErrNoRules
	}

	if err := set.duplicateIDs(); err != nil {
		return nil, err
	}
	return set, nil
}

// supported rejects rules this version cannot evaluate correctly.
//
// v1 is stateless single-event matching: each container sees an arbitrary
// slice of the queue and keeps no cross-event state, so a rule counting
// events over a timeframe cannot be answered -- not approximately, but at
// all. Loading such a rule and never firing it would leave a detection that
// appears deployed and covers nothing, which is the failure mode this whole
// file is arranged to avoid. Rejecting at load time turns it into a deploy
// failure with the file name in it.
func supported(rule sigma.Rule) error {
	for i, cond := range rule.Detection.Conditions {
		if cond.Aggregation != nil {
			return fmt.Errorf("condition %d uses an aggregation (count/sum/avg/near), "+
				"which needs cross-event state this engine does not keep", i)
		}
	}
	if rule.Detection.Timeframe != 0 {
		return fmt.Errorf("rule sets a timeframe of %s, which needs cross-event state "+
			"this engine does not keep", rule.Detection.Timeframe)
	}
	if len(rule.Detection.Conditions) == 0 {
		// Parses cleanly, evaluates cleanly, matches nothing, ever. This is
		// also the shape a Sigma correlation rule arrives in: the
		// "correlation" key lands in AdditionalFields and Detection comes
		// back empty.
		return errors.New("rule has no detection condition")
	}
	if _, ok := rule.AdditionalFields["correlation"]; ok {
		return errors.New("correlation rules need cross-event state this engine does not keep")
	}

	for name, search := range rule.Detection.Searches {
		if len(search.Keywords) > 0 {
			// sigma-go returns "keywords unsupported" for every event, so the
			// rule would register and then produce one rule error per event
			// forever.
			return fmt.Errorf("search %q uses keywords, which sigma-go does not implement", name)
		}
		for _, matcher := range search.EventMatchers {
			for _, fm := range matcher {
				if err := supportedModifiers(fm); err != nil {
					return fmt.Errorf("search %q: %w", name, err)
				}
			}
		}
	}
	return nil
}

// supportedModifiers pre-flights the exact comparator lookup the evaluator
// performs per event.
//
// An unimplemented modifier -- windash, base64offset, utf16, expand, cidrv6
// and others, depending on the sigma-go build -- is not a load-time failure in
// sigma-go: it surfaces as an error on every single event. That reads as a
// noisy rule rather than as a rule that cannot work, so it is checked here
// where the file name is still in scope.
func supportedModifiers(fm sigma.FieldMatcher) error {
	mods := fm.Modifiers
	// "all" is a quantifier over the values, not a comparator, and sigma-go
	// strips it before the lookup.
	if len(mods) > 0 && mods[len(mods)-1] == "all" {
		mods = mods[:len(mods)-1]
	}
	if _, err := modifiers.GetComparator(fm.Field, nil, mods...); err != nil {
		return fmt.Errorf("field %q: %w", fm.Field, err)
	}

	// A %placeholder% value needs an expander, which this engine does not
	// configure. Without one the rule silently compares against the literal
	// string with percent signs.
	for _, v := range fm.Values {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if len(s) > 2 && strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%") {
			return fmt.Errorf("field %q uses placeholder %s and no expander is configured", fm.Field, s)
		}
	}
	return nil
}

// identity returns a stable rule identifier.
//
// The Sigma id is preferred because it survives a file rename. Falling back to
// the file name keeps the deterministic alert id working for rules that omit
// it, at the cost of changing every alert id if the file is renamed.
func identity(rule sigma.Rule, file string) string {
	if id := strings.TrimSpace(rule.ID); id != "" {
		return id
	}
	if t := strings.TrimSpace(rule.Title); t != "" {
		return t
	}
	return strings.TrimSuffix(path.Base(file), path.Ext(file))
}

// duplicateIDs rejects two rules sharing an identifier.
//
// The alert id is derived from the rule id plus the object key and record
// index, so duplicates would collapse two different detections into one alert
// and the second would look like a redelivery of the first.
func (s *Set) duplicateIDs() error {
	seen := map[string]string{}
	var dupes []string
	for _, r := range s.rules {
		if first, ok := seen[r.meta.RuleID]; ok {
			dupes = append(dupes, fmt.Sprintf("%q in both %s and %s", r.meta.RuleID, first, r.meta.File))
			continue
		}
		seen[r.meta.RuleID] = r.meta.File
	}
	if len(dupes) > 0 {
		return fmt.Errorf("duplicate rule ids would collapse distinct alerts:\n  - %s",
			strings.Join(dupes, "\n  - "))
	}
	return nil
}

// RuleError is one rule failing on one event.
type RuleError struct {
	RuleID string
	File   string
	Err    error
}

func (e RuleError) Error() string {
	return fmt.Sprintf("rule %s (%s): %v", e.RuleID, e.File, e.Err)
}

// Match evaluates one event against every rule.
//
// A rule that errors or panics is reported and skipped, and the remaining
// rules still run. The alternative -- failing the event -- would let one
// broken rule stop detection for every other rule in the source, and since
// the failure is not something a redelivery can fix, the object would loop to
// the DLQ and take all its events with it.
//
// The cost of that choice is that a consistently failing rule is a detection
// that is silently off, so the returned errors must be logged and
// detection_rule_errors_total must be alarmed on. It should always be zero:
// Compile already rejects every load-time-detectable cause (aggregations,
// keywords, unimplemented modifiers, placeholders) and the decoder normalises
// the number types that panic sigma-go's comparators.
//
// A cancelled context is returned as an error rather than counted, because it
// means shutdown, not a rule problem.
func (s *Set) Match(ctx context.Context, event map[string]any) ([]Match, []RuleError, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	var (
		matches  []Match
		ruleErrs []RuleError
	)
	for _, r := range s.rules {
		matched, err := r.evaluate(ctx, event)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ruleErrs, ctxErr
			}
			ruleErrs = append(ruleErrs, RuleError{RuleID: r.meta.RuleID, File: r.meta.File, Err: err})
			continue
		}
		if matched {
			matches = append(matches, r.meta)
		}
	}
	return matches, ruleErrs, nil
}

// evaluate runs one rule, converting a panic into an error.
//
// sigma-go panics rather than returning an error on several inputs: an
// unhandled search-node type, and a numeric modifier against a value type its
// comparator does not expect. Both were reproduced against v0.6.6. In a
// single-process Fargate task an unrecovered panic means the task dies, ECS
// restarts it, SQS redelivers the same object, and the deployment crash-loops
// with detection off for every rule in the source. Containing it to one rule
// costs one silent detection and one alarmable counter.
func (c compiled) evaluate(ctx context.Context, event map[string]any) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during evaluation: %v", r)
		}
	}()
	result, err := c.evaluator.Matches(ctx, evaluator.Event(event))
	if err != nil {
		return false, err
	}
	return result.Match, nil
}

// Len is the number of compiled rules.
func (s *Set) Len() int { return len(s.rules) }

// All returns each rule's metadata, for the startup log.
func (s *Set) All() []Match {
	out := make([]Match, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r.meta)
	}
	return out
}

// IDs returns every rule id, sorted.
func (s *Set) IDs() []string {
	out := make([]string, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r.meta.RuleID)
	}
	sort.Strings(out)
	return out
}
