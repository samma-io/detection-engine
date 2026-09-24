package decode

import (
	"encoding/json"
	"strconv"
	"strings"
)

// MaxFlattenDepth bounds alias generation. Real events nest three or four
// levels; the cap stops a pathological event from producing a huge alias map.
const MaxFlattenDepth = 12

// unmarshalEvent decodes one record into the shape sigma-go can actually
// evaluate.
//
// Numbers are the subtlety. A plain json.Unmarshal makes every number a
// float64, and sigma-go's string coercion runs it through fmt.Sprint, so
// GitHub's created_at of 1780578968354 becomes "1.780578968354e+12" and an
// equality rule on the literal integer silently never matches. Verified
// against sigma-go v0.6.6.
//
// json.Decoder.UseNumber alone is worse, not better: json.Number has
// reflect.Kind String but is not a string, and sigma-go's numeric coercion
// does a `left.(string)` type assertion, so any |gt / |gte / |lt / |lte
// modifier against a json.Number panics outright. int64 does not work either
// -- the coercion only handles reflect.Int and reflect.Float64.
//
// So: decode with UseNumber, then convert every number to int when it is
// integral and float64 otherwise. That pair is the only one that satisfies
// both the stringification path and the numeric-comparison path.
func unmarshalEvent(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	obj, ok := normalizeNumbers(v).(map[string]any)
	if !ok {
		return nil, errNotAnObject
	}
	return obj, nil
}

// normalizeNumbers rewrites json.Number values in place through the tree.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeNumbers(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = normalizeNumbers(val)
		}
		return t
	case json.Number:
		// Atoi yields exactly int, which is the kind sigma-go's numeric
		// coercion accepts. ParseInt would give int64, which it does not.
		if n, err := strconv.Atoi(t.String()); err == nil {
			return n
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		// Neither an int nor a float64 can hold it (a huge literal). Keep the
		// digits as a string rather than losing precision silently.
		return t.String()
	default:
		return v
	}
}

// MatchView returns the event as sigma-go must see it: the original fields
// plus a dot-joined alias for every nested leaf.
//
// This exists because sigma-go's field lookup is a single flat map index --
// eventValue() does evt[key] and nothing more. A rule written as
//
//	userIdentity.type: AssumedRole
//
// looks up the literal top-level key "userIdentity.type", finds nothing, and
// reports a clean non-match. Verified against v0.6.6: the nested event does
// not match, the same event with a flattened alias does. Nearly every
// upstream SigmaHQ rule for CloudTrail, GCP and Workspace uses dotted paths,
// so without this the engine would load hundreds of rules, report them all on
// /rules, and be incapable of firing any of them.
//
// The alias map is deliberately a separate map from the event itself. Adding
// the aliases in place would put them in the alert's raw event, roughly
// doubling its size and presenting consumers with fields the source never
// emitted.
//
// Leaf values are shared, not copied, so the cost is keys rather than a deep
// copy. That makes the view read-only by contract: nothing may mutate a leaf
// reached through it, or the alert's event would change underneath.
func MatchView(event map[string]any) map[string]any {
	view := make(map[string]any, len(event)*2)
	for k, v := range event {
		view[k] = v
	}
	for k, v := range event {
		flatten(view, k, v, 1, event)
	}
	return view
}

// flatten walks one value, adding dot-joined aliases for nested leaves.
func flatten(view map[string]any, prefix string, v any, depth int, original map[string]any) {
	if depth > MaxFlattenDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			key := prefix + "." + k
			addAlias(view, key, val, original)
			flatten(view, key, val, depth+1, original)
		}
	case []any:
		// An array of objects is flattened element-wise into the same alias,
		// so CloudTrail's resources: [{ARN: a}, {ARN: b}] answers a rule
		// written as resources.ARN. sigma-go expands a slice-valued field
		// across its elements on its own -- verified -- so collecting the
		// leaves into one slice is enough.
		for _, el := range t {
			if m, ok := el.(map[string]any); ok {
				for k, val := range m {
					key := prefix + "." + k
					addAlias(view, key, val, original)
					flatten(view, key, val, depth+1, original)
				}
			}
		}
	}
}

// addAlias records an alias without ever shadowing a field the source really
// emitted.
//
// If Vector ever emits a literal "userIdentity.type" key alongside the nested
// object, the real field wins: an alias must never change the meaning of a
// field that exists. Repeated aliases (an array of objects) accumulate into a
// slice, which is the shape sigma-go expands.
func addAlias(view map[string]any, key string, val any, original map[string]any) {
	if _, isReal := original[key]; isReal {
		return
	}
	existing, ok := view[key]
	if !ok {
		view[key] = val
		return
	}
	if slice, ok := existing.([]any); ok {
		view[key] = append(slice, val)
		return
	}
	view[key] = []any{existing, val}
}
