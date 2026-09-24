# sigmaimport

Brings upstream Sigma rules into `rules/<lane>/`.

```
go run ./hack/sigmaimport -sigma <dir> -fixtures <dir>  -lane aws    -root .
go run ./hack/sigmaimport -sigma <dir> -samples <file>  -lane github -root .
go run ./hack/sigmaimport ... -apply -sigma-ref <sha> -fixtures-ref <sha>
```

Two ways to get a sidecar, in order of preference:

- **`-fixtures`** — TrailAlerts records keyed by SigmaHQ rule id. CloudTrail
  only; there is no equivalent corpus for any other lane.
- **`-samples`** — NDJSON of real records pulled from the filtered bucket. Works
  for every lane, and proves the rule against what the source actually emits.

A rule that matches nothing in the sample is **reported, not imported**. It is
not necessarily a bad rule -- the event may simply be rare -- but it is unproven
here, and saying so is more useful than asserting coverage. Widen the sample
window before concluding a rule is irrelevant.

Without `-apply` it reports and writes nothing.

The Go toolchain here runs in a container, so the upstream corpora must be
staged **inside the repo** for the tool to see them. `.import-src/` is
gitignored for that; upstream is never vendored.

```
mkdir -p .import-src/sigma .import-src/fixtures
cp <sigma>/rules/cloud/aws/cloudtrail/*.yml .import-src/sigma/
cp <trailalerts>/rules/sigma_rules/*        .import-src/fixtures/
```

## Why it is built this way

**Admission is the engine's own predicate.** It calls `internal/rules.Compile`,
not a copy of its logic. A reimplementation drifts on the first sigma-go bump,
and drifts silently in the direction that matters — accepting a rule that
cannot fire.

**Test events come from upstream fixtures, not from the rule.** TrailAlerts
ships real CloudTrail records keyed by the same rule ids SigmaHQ uses, so 41 of
57 CloudTrail rules arrive with a realistic firing case and a realistic
non-firing one. A sidecar synthesised from the rule's own selection proves only
that the rule matches itself, which defeats the single most valuable gate in
this repo. A rule with no fixture is **rejected**, not stubbed.

**Upstream ids are kept.** `rulecheck` enforces global id uniqueness and the
alert id derives from the rule id, so ids must be stable forever. Keeping
upstream's makes a re-import a diff rather than a duplicate, and keeps the join
back to the upstream rule checkable.

**`declined.yml` is load-bearing.** Absence from the tree is exactly what "new"
looks like, so without it a re-import silently reverses every curation decision.
Measured: a second run offered 14 rules back, six of them duplicates and four
unable to fire.

## The gates, in order

| Gate | Catches |
|---|---|
| declined list | decisions already made |
| id already present | a rule we have |
| `rules.Compile` | aggregations, `timeframe`, correlation, `keywords`, unimplemented modifiers, placeholders |
| glob lint | `*` in a value — matched literally here, so a pure silent non-match |
| fixture required | rules we could not honestly claim coverage for |

What it does **not** catch is semantic duplication — an upstream rule that
duplicates one of ours has a different id by construction.
`TestRules_DoNotSemanticallyDuplicateEachOther` is that guard, and it runs
against the imported tree, not here.
