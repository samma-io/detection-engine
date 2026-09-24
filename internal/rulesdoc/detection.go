// Package rulesdoc renders the committed rules tree as a human-readable
// catalogue.
//
// It exists because the thing an on-call engineer needs at 3am -- "what does
// this alert mean, and is it likely to be real?" -- is spread across a Sigma
// YAML file they have to find, parse and interpret under pressure. The
// catalogue answers it in one page.
//
// The rendering is deliberately derived from the rules rather than written
// alongside them. A hand-maintained catalogue is wrong within a week, and a
// confidently wrong catalogue is worse than none: it is read at exactly the
// moment nobody has time to check it against the source.
package rulesdoc

import (
	"fmt"
	"sort"
	"strings"

	sigma "github.com/bradleyjkemp/sigma-go"
)

// describeCondition renders a rule's condition as a sentence, substituting each
// search identifier with a description of what that search actually matches.
//
// Rules almost always have exactly one condition. Where there are several,
// Sigma treats them as alternatives, so they are joined with "or".
// notPrefix marks a negated sub-expression so joinExprs can fold it into the
// preceding connective.
const notPrefix = "**not** "

func describeCondition(rule sigma.Rule) string {
	parts := make([]string, 0, len(rule.Detection.Conditions))
	for _, cond := range rule.Detection.Conditions {
		if s := describeExpr(rule, cond.Search, false); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " **or** ")
}

// describeExpr walks the condition AST. nested controls bracketing: the
// top-level expression does not need parentheses, inner ones usually do.
func describeExpr(rule sigma.Rule, expr sigma.SearchExpr, nested bool) string {
	switch e := expr.(type) {
	case sigma.And:
		return joinExprs(rule, e, " **and** ", nested)
	case sigma.Or:
		return joinExprs(rule, e, " **or** ", nested)
	case sigma.Not:
		return notPrefix + describeExpr(rule, e.Expr, true)
	case sigma.SearchIdentifier:
		return describeSearch(rule, e.Name, nested)
	case sigma.OneOfIdentifier:
		return describeSearch(rule, e.Ident.Name, nested)
	case sigma.AllOfIdentifier:
		return describeSearch(rule, e.Ident.Name, nested)
	case sigma.OneOfPattern:
		return describeMatching(rule, e.Pattern, " **or** ", nested)
	case sigma.AllOfPattern:
		return describeMatching(rule, e.Pattern, " **and** ", nested)
	case sigma.OneOfThem:
		return describeAll(rule, " **or** ", nested)
	case sigma.AllOfThem:
		return describeAll(rule, " **and** ", nested)
	}
	return ""
}

func joinExprs(rule sigma.Rule, exprs []sigma.SearchExpr, sep string, nested bool) string {
	var out string
	for _, sub := range exprs {
		s := describeExpr(rule, sub, true)
		if s == "" {
			continue
		}
		if out == "" {
			out = s
			continue
		}
		// "**and** **not** x" is two bold runs where the reader wants one
		// connective. Fold them into "**and not** x".
		if rest, ok := strings.CutPrefix(s, notPrefix); ok {
			out += strings.TrimSuffix(sep, "** ") + " not** " + rest
			continue
		}
		out += sep + s
	}
	if out == "" {
		return ""
	}
	if nested && strings.Contains(out, "**") {
		return "(" + out + ")"
	}
	return out
}

// describeMatching resolves `1 of selection_*` the way the evaluator does, by
// matching search names against the pattern.
func describeMatching(rule sigma.Rule, pattern, sep string, nested bool) string {
	names := matchingSearchNames(rule, pattern)
	return describeNames(rule, names, sep, nested)
}

func describeAll(rule sigma.Rule, sep string, nested bool) string {
	names := make([]string, 0, len(rule.Detection.Searches))
	for name := range rule.Detection.Searches {
		names = append(names, name)
	}
	sort.Strings(names)
	return describeNames(rule, names, sep, nested)
}

func describeNames(rule sigma.Rule, names []string, sep string, nested bool) string {
	parts := make([]string, 0, len(names))
	for _, n := range names {
		if s := describeSearch(rule, n, true); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	out := strings.Join(parts, sep)
	if nested {
		return "(" + out + ")"
	}
	return out
}

// describeSearch renders one named search.
//
// A search is a list of event matchers, any one of which may match; each event
// matcher is a set of field conditions that must all hold.
func describeSearch(rule sigma.Rule, name string, nested bool) string {
	search, ok := rule.Detection.Searches[name]
	if !ok {
		return ""
	}

	// Keywords are rejected at load, so they cannot appear in a committed
	// rule. Named rather than silently dropped, so the catalogue never renders
	// an empty condition for a rule that has one.
	if len(search.Keywords) > 0 {
		return "_(keyword search — unsupported by this engine)_"
	}

	matchers := make([]string, 0, len(search.EventMatchers))
	for _, em := range search.EventMatchers {
		fields := make([]string, 0, len(em))
		for _, fm := range em {
			fields = append(fields, describeFieldMatcher(fm))
		}
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 {
			matchers = append(matchers, fields[0])
			continue
		}
		matchers = append(matchers, "("+strings.Join(fields, " and ")+")")
	}

	if len(matchers) == 0 {
		return ""
	}
	if len(matchers) == 1 {
		// Parentheses around the whole condition are noise when there is
		// nothing to separate it from.
		if !nested {
			return strings.TrimSuffix(strings.TrimPrefix(matchers[0], "("), ")")
		}
		return matchers[0]
	}
	out := strings.Join(matchers, " or ")
	if nested {
		return "(" + out + ")"
	}
	return out
}

// comparatorPhrase maps a Sigma modifier to English. The set is exactly what
// sigma-go implements; anything else is rejected at load, so an unknown
// modifier here means the admission check and this table have diverged.
var comparatorPhrase = map[string]string{
	"contains":   "contains",
	"startswith": "starts with",
	"endswith":   "ends with",
	"re":         "matches the regular expression",
	"cidr":       "is inside",
	"gt":         "is greater than",
	"gte":        "is at least",
	"lt":         "is less than",
	"lte":        "is at most",
	"base64":     "is the base64 of",
}

func describeFieldMatcher(fm sigma.FieldMatcher) string {
	mods := fm.Modifiers

	// `all` is a quantifier over the values, not a comparator, and sigma-go
	// strips it before the comparator lookup. Mirrored here so the phrasing
	// says "all of" rather than naming a modifier that does not exist.
	requiresAll := false
	if len(mods) > 0 && mods[len(mods)-1] == "all" {
		requiresAll = true
		mods = mods[:len(mods)-1]
	}

	phrase := "is"
	for _, m := range mods {
		if p, ok := comparatorPhrase[m]; ok {
			phrase = p
		}
	}

	field := "`" + fm.Field + "`"
	values := make([]string, 0, len(fm.Values))
	for _, v := range fm.Values {
		values = append(values, "`"+fmt.Sprint(v)+"`")
	}

	switch {
	case len(values) == 0:
		return field + " is present"
	case len(values) == 1:
		return field + " " + phrase + " " + values[0]
	case requiresAll:
		return field + " " + phrase + " all of " + strings.Join(values, ", ")
	default:
		verb := phrase
		if verb == "is" {
			verb = "is one of"
		} else {
			verb += " any of"
		}
		return field + " " + verb + " " + strings.Join(values, ", ")
	}
}
