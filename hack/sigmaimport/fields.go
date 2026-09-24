package main

import (
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"

	"github.com/samma-io/detection-engine/internal/decode"
)

// The difference that decides whether an upstream rule is worth importing:
//
//	field absent from the sample   -> EITHER a taxonomy mismatch that means the
//	                                  rule can never fire here, OR a field that
//	                                  only appears on the rare event the rule is
//	                                  about. A day of github traffic carries no
//	                                  `visibility` field because no repository
//	                                  changed visibility -- which says nothing
//	                                  about the rule. Worth investigating, never
//	                                  worth concluding from one window.
//	field present, value unseen    -> the rule CAN fire, it simply describes
//	                                  something that has not happened yet.
//	                                  Rare is the point; repo.destroy should
//	                                  not appear in a normal day.
//
// Rejecting both as "unproven" conflates a broken rule with a quiet week, which
// is the single most misleading thing this tool could do.

// fieldsUsedBy returns every event field a rule matches on.
func fieldsUsedBy(r sigma.Rule) []string {
	seen := map[string]bool{}
	for _, search := range r.Detection.Searches {
		for _, em := range search.EventMatchers {
			for _, fm := range em {
				if fm.Field != "" {
					seen[fm.Field] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// knownFields is every field name the lane actually emits, taken from the
// flattened match view so dotted paths resolve exactly as they would at match
// time.
func (s *sampleSet) knownFields() map[string]bool {
	out := map[string]bool{}
	for _, rec := range s.Records {
		for k := range decode.MatchView(rec) {
			out[k] = true
		}
	}
	return out
}

// missingFields reports which of a rule's fields never appear in the sample,
// after fieldmappings are applied -- a mapped field is present under its mapped
// name, which is the whole point of the mapping.
func missingFields(r sigma.Rule, known map[string]bool, cfg []sigma.Config) []string {
	mapped := map[string][]string{}
	for _, c := range cfg {
		for from, to := range c.FieldMappings {
			mapped[from] = append(mapped[from], to.TargetNames...)
		}
	}

	var missing []string
	for _, f := range fieldsUsedBy(r) {
		if known[f] {
			continue
		}
		ok := false
		for _, target := range mapped[f] {
			if known[target] {
				ok = true
				break
			}
		}
		if !ok {
			missing = append(missing, f)
		}
	}
	return missing
}

func joinShort(ss []string, max int) string {
	if len(ss) > max {
		ss = append(ss[:max:max], "...")
	}
	return strings.Join(ss, ", ")
}
