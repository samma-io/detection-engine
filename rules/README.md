# Detection rules

Before writing rules for a new lane, read
[`../docs/RULE-SOURCES.md`](../docs/RULE-SOURCES.md) — which upstream corpus
covers which log source, what each one's licence and format is, and which of
them this engine can actually use.

One directory per log source (a *lane*). Each engine loads only its own
`<lane>/` prefix at container start, from one of two places:

- **baked into the image** at `/rules` (the default) -- `docker build` copies
  this tree without the `.tests.yml` sidecars and `examples/`;
- **the rules bucket**, when [samma-io/aws-siem](https://github.com/samma-io/aws-siem)
  is given a `rules_dir` and uploads it. That directory must contain only
  `<lane>/sigma-config.yml` and rule files: a sidecar there is loaded as a rule
  and the engine refuses to start.

`rules/examples/` is documentation, not a lane: it is never baked in and the
gate skips it.

```
rules/<source>/sigma-config.yml     # sigma-go Config: logsource + field mappings
rules/<source>/<rule>.yml           # a Sigma rule
rules/<source>/<rule>.tests.yml     # REQUIRED: cases proving the rule fires
```

## Every rule must have a `.tests.yml` with at least one firing case

This is enforced by `TestRules_EveryRuleHasAPositiveTestCase`, and it is not
bureaucracy. A Sigma rule that references a field the source does not emit does
not error — it simply never matches, forever, silently. There is no runtime
signal for it: the engine reports the rule as loaded, `/rules` lists it, and no
metric distinguishes "no attacks" from "this rule cannot fire". A positive test
case against a realistic event is the only thing that catches it.

The same class of bug exists on the infrastructure side (an `=` in an S3
notification `filter_prefix` silently matches nothing). Assume the silent-failure reading is
the likely one.

## Field shapes

Rules are written against what Vector actually puts in the filtered bucket,
which is the vendor-native shape plus a `source` field:

- **aws** — native CloudTrail records, flattened out of `Records[]`:
  `eventName`, `eventSource`, `userIdentity.type`, `sourceIPAddress`,
  `requestParameters.*`, `errorCode`, `recipientAccountId`.
- **github** — native GitHub audit log entries: `action`, `actor`, `actor_ip`,
  `org`, `repo`, `created_at` (epoch millis), `operation_type`,
  `programmatic_access_type`.
- **cloudflare** — ingester records (the vendor shape plus `_partition`,
  `_event_time`, `_dedupe_key`) under Vector's SaaS envelope: `feed` (one of
  `access`, `audit`, `devices`, `firewall`, `gateway_dns`, `gateway_http`,
  `gateway_network`, or `logpush` from the Logpush producer), `event_time`,
  `actor_email`, `search_text`. Firewall records' own `source` (`waf`,
  `botFight`, ...) is renamed to `cf_source`, so `source` is always
  `cloudflare`. The feeds share no schema
  -- `action` is an object on `audit` (`action.type`, `action.result`) and a
  string on `access` and `firewall` -- so every rule pins `feed`, and
  `TestRules_MultiFeedLanesPinTheFeed` enforces it. The reference shapes are
  the golden files in samma-io/ingester `internal/source/cloudflare/golden/`.

- **k8s** — Kubernetes audit events (`audit.k8s.io/v1` `Event`), one per
  message on `samma.logs.k8s` (NATS transport only): `kind`, `verb`,
  `requestURI`, `user.username`, `impersonatedUser.username` (present only on an
  impersonated request), `objectRef.resource`, `objectRef.subresource`,
  `objectRef.namespace`, `objectRef.name`, `requestObject.*`,
  `responseStatus.code`. Exec, attach, port-forward and token requests are
  `verb: create` on the parent resource, so a rule about creating a pod or a
  serviceaccount must pin the collection URI (`requestURI|re: /pods(\?|$)`)
  or it also fires on every one of those.

- **scanner** — Samma scanner messages relayed to `samma.logs.scanner` (NATS
  transport only). samma-io/detect publishes schema v2: `schema:
  samma.io/scan/v2`, `kind` (`finding` or `run`), `checkId`, `severity`,
  `endpoint.host`/`endpoint.port`/`endpoint.scheme`, `title`, `evidence`.
  The classic nmap and nikto images still publish legacy v1 records with no
  `schema` (nmap: `type: nmap`, `scanner: nmap_port`, `port`, `protocol`;
  nikto: `type: Nikto`, `OSVDB`, `nikto_url`, `finding`). Pin `kind: finding`
  or the legacy `type`, so lifecycle messages (`kind: run`,
  `event: scanner_start`, `scan: done`) never alert.

- **osquery** — osquery-client results on `samma.logs.osquery` (NATS transport
  only), one result row per message: `name` (the query, e.g.
  `samma_process_events`, `samma_users`), `action` (`added` or `removed`),
  `counter` (`0` on the query's first run on that host), `hostIdentifier`,
  `unixTime`, and the row under `columns.*`, every value a string. Pin `name`.
  Rules on state tables (users, keys, crontab, ...) exclude `counter: 0` so a
  new host's baseline does not alert; rules on the event tables
  (`samma_process_events`, `samma_socket_events`, `samma_file_events`) must
  not, because those rows are real events even on the first run. The queries
  are in samma-io/osquery-client `config/osquery.conf`.

- **traefik** — Traefik JSON access logs on `samma.logs.svc.traefik` (stream
  `SIEM_SERVICES`, NATS transport only; set `ENGINE_NATS_STREAM` and
  `ENGINE_NATS_SUBJECT`), from pods labelled `samma.io/detection: traefik` via
  samma-io/deploy `siem/61-k8s-log-router.yaml`. Traefik's own field names:
  `ClientHost`, `RequestMethod`, `RequestHost`, `RequestPath` (the URI with its
  query string, not decoded), `DownstreamStatus` (a number), `RouterName`,
  `ServiceName`, `entryPointName`, plus `request_User-Agent` when the access log
  keeps that header. Traefik's own log lines share the subject and have no
  `RequestPath`, so pin a request field.

Dotted paths such as `userIdentity.type` work because the engine builds a
flattened match view of every event; see `internal/decode/normalize.go`.
Upstream SigmaHQ rules for these products can usually be dropped in unchanged,
but **verify with a test case** rather than assuming.

## Unsupported rule features

The loader rejects these at startup rather than loading a rule that cannot
fire:

- aggregations (`count()`, `sum()`, `avg()`, `near`) and `timeframe` — v1 is
  stateless single-event matching
- `correlation` rules
- `keywords` searches — sigma-go does not implement them
- unimplemented field modifiers
- `%placeholder%` values — no expander is configured
- a missing or duplicate rule `id` — the alert id is derived from it

## Wildcards do not work — this one the loader cannot catch

The Sigma spec says `*` and `?` are wildcards in a value. **sigma-go does not
implement that.** The default comparator is
`strings.EqualFold(CoerceString(actual), CoerceString(expected))`, and
`|contains`/`|startswith`/`|endswith` are plain `strings.Contains`/`HasPrefix`/
`HasSuffix`. A `*` in a value is a literal asterisk.

Unlike everything in the list above, this is not rejected at load. The rule
compiles, loads, and appears on `/rules` — it is simply wrong forever, and
which way it is wrong depends on where the search sits:

- in a **selection**, the rule never fires;
- in a **filter under `not`**, the filter never matches, so the negation always
  holds and the rule fires on everything the selection matched. This is the
  dangerous one, because it looks like the rule is working.

`TestRules_NoGlobsInDetectionValues` is the guard. Use `|re` when you need a
pattern, or narrow to a literal with `|contains`/`|startswith`/`|endswith`.

Note that `*` in a **condition** is fine and supported —
`condition: selection and not 1 of filter_*` matches *search names* via
`path.Match`, which sigma-go does implement. Only values are affected.

A value whose asterisk is genuinely part of the string — an IAM policy
`"arn:aws:s3:::bucket/*"`, say — goes in
`internal/rulecheck/testdata/wildcard_exceptions.yml` with a reason recording
the real event you checked it against.

## Rules that carry facts about one organisation

Some useful rules only work once they know something about the estate they
watch: which account ids are the Organizations management accounts, which
email domain SSO identities carry, which 1Password vault holds the break-glass
credentials. Those are point-in-time facts about an organisation rather than
about the log format, and they cannot ship with real values in a public rule
set.

They live in [`examples/org-specific/`](examples/org-specific/README.md) with
placeholder values and a README describing how to copy one into a lane and fill
it in. The gate ignores that directory; a rule copied into a lane is checked
like any other, and its sidecar must prove the filled-in values match.

Such lists drift. A new management account, a renamed vault or a second email
domain is simply not covered -- silently, because the rule keeps working for
everything still on the list. Re-check them when someone asks whether coverage
is current; no test can answer that, because every value in the rule is
well-formed and the ones missing look exactly like the ones that were never
there.
