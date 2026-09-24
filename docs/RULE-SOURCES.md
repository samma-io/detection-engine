# Where to find rules for a log source

Read this **before** writing rules for a new lane. Most of what you need
already exists somewhere, and the expensive part of a rule is never the
detection logic -- it is knowing which fields the source actually emits.

Counts were measured in September 2026. They drift; re-measure before planning
an import wave.

## Coverage by log source

Counts are rules that target that product. "Usable" accounts for this engine's
constraints -- stateless single-event matching, no aggregation, no wildcards in
values. See `rules/README.md`.

| Log source | Lane here | SigmaHQ | Elastic (stateless) | TrailAlerts |
|---|---|---:|---:|---:|
| **aws / cloudtrail** | `aws` | 57 | 210 (95) | 52 |
| **github / audit** | `github` | 15 | 19 (0) | - |
| **gcp / audit** | `gcp` | 16 | 74 (52) | - |
| **workspace** (Google Workspace) | `workspace` | 10 | 27 (18) | - |
| **slack** | `slack` | - | - | - |
| **onepassword** | `onepassword` | - | - | - |
| **dns** (Route 53 Resolver) | `dns` | - | - | - |
| **alb** (connection logs) | `alb` | - | - | - |
| okta | not a lane | 21 | 50 (26) | - |
| azure / m365 | not a lane | 123 / 19 | 143 / 48 | - |
| kubernetes | not a lane | 16 | 43 (22) | - |

**A count in a corpus is not coverage until the schema matches.** Slack is the
canonical example: the vendor corpora that exist for it bind to the Enterprise
Grid audit log, while a Business+ workspace receives only `team.accessLogs` and
`team.integrationLogs`, which share no fields with it. Importing them would
produce rules that can never fire. Check the schema per lane before counting.

## The corpora

### SigmaHQ -- <https://github.com/SigmaHQ/sigma>

Native Sigma, so **mechanically importable** with `hack/sigmaimport`. Licence
**DRL-1.1** (attribution required; each imported rule keeps its `author` and
`references`). The reference corpus, and the only one whose format matches this
engine's.

Gotchas, all measured: 2 CloudTrail rules use `|fieldref`, which sigma-go does
not implement at all; 3 more use `*` inside a value, which this engine matches
literally (see `rules/README.md`). 1 GCP rule uses `keywords`, rejected at
load. GCP rules use the taxonomy field `gcp.audit.method_name` and need the
fieldmapping in `rules/gcp/sigma-config.yml`.

### TrailAlerts -- <https://github.com/adanalvarez/TrailAlerts>

52 **native Sigma** CloudTrail rules, Apache-2.0. 41 share SigmaHQ rule ids, so
it is largely a curated SigmaHQ subset -- but two things make it worth keeping:

1. **11 rules unique to it**, several of them good (flow log deletion,
   `LeaveOrganization`, resolver query-log deletion, short-expiry lifecycle).
2. **52 `*_tests.json` fixtures with 107 realistic CloudTrail events**, split
   `should_match` / `should_not_match`. Writing realistic test events is the
   actual bottleneck in every import wave, and because the rule ids match
   SigmaHQ's, these fixtures seed sidecars for SigmaHQ imports too
   (`hack/sigmaimport -fixtures`).

### Elastic -- <https://github.com/elastic/detection-rules>

Large, but rules are KQL/EQL/ES|QL. Only the `type = "query"` ones are stateless
enough to port, and even those need manual translation. Treat as an **idea
source**, not an import. Licence: Elastic Licence 2.0 -- copy intent, not text.

### Vendor Python-rule corpora

Several commercial SIEM vendors publish their detections as Python
`rule(event)` functions with YAML metadata under Apache-2.0. They are not
mechanically importable, but far more convertible than that suggests: the
typical CloudTrail shape is `eventName.startswith("DeleteBucket") and
success(event)`, which is a direct Sigma translation (`|startswith` plus an
`errorCode` filter), and almost none use stateful helpers or time windows.
They cover hundreds of CloudTrail event names SigmaHQ does not -- IAM policy
attachment, RDS snapshot copy, Secrets Manager retrieval, SSM, VPC endpoints,
KMS aliases -- and are the highest-yield remaining source for the `aws` lane.
Check each corpus's licence and schema binding before converting.

### Wazuh -- <https://github.com/wazuh/wazuh-ruleset>

`rules/0350-amazon_rules.xml`, 56 rules. **Assessed and rejected as a rule
source.** It is a log *classifier*, not a detection set: the bulk are
`AWS Cloudtrail: $(eventSource) - $(eventName)` taggers, only 2 key on an event
name, and its genuinely detection-shaped rules are frequency-based, which this
engine cannot express. Its GuardDuty and Macie rules are still worth reading
for a sane severity mapping.

### StreamAlert -- <https://github.com/airbnb/streamalert>

**Effectively dormant** -- last push October 2023. Python rules. Little
CloudTrail, but `rules/community/` has GitHub (10), Duo (8), OneLogin (3) and
osquery rules. Worth a look only for a Duo or OneLogin lane. Licence: Apache-2.0.

## What this repository has taken

| From | What | Where |
|---|---|---|
| AWS Security Hub `CloudWatch.1-14` | 10 CIS baseline rules | `rules/aws/` |
| TrailAlerts | 4 rules (flow logs, org leave, resolver logs, lifecycle) | `rules/aws/` |
| SigmaHQ | CloudTrail rules imported with `hack/sigmaimport` | `rules/aws/` |

Imported rules keep their upstream id, so provenance is checkable: search the
id in the upstream repo. Rules written here carry `author: samma-io`.

## What a lane actually carries

Measure it from the filtered bucket, not from the ingest config -- the two
diverge quietly. A feed can stop at source (a vendor plan change, a revoked
token) and every rule pinned to it becomes dead without any error. Before an
import wave, pull a day of records per lane and list the distinct `feed`,
`eventSource` or `action` values; write test events from those records.

Two measured examples of why:

- A Slack `integrationlogs` feed stopped at source one day, which silently
  disabled the rule watching third-party apps -- on Business+ that feed is the
  only visibility into apps reaching the workspace.
- 1Password `itemusages` volume in one estate was almost entirely a single
  automation repeatedly touching one item. A rule on `action: share` would
  look like exfil coverage and be noise. Vault-scoped rules need the vault
  uuids, which are not in the data -- see `rules/examples/org-specific/`.

## Adding a lane

1. Find the product in the table above. If it is missing, check the vendor
   corpora first -- between them they cover Okta, Auth0, Notion, Snowflake,
   Zoom, Teleport, Tailscale, CrowdStrike and dozens more.
2. Check the licence before copying rule *text*. Detection *logic* is not
   generally copyrightable; wording and structure are. Attribute in the rule's
   `references:` either way.
3. Read `rules/README.md` for what this engine cannot express, then discard
   candidates that need aggregation, wildcards in values or field-to-field
   comparison.
4. Add the lane to `internal/source/registry.go`, to `detectionSources` in
   `internal/source/registry_test.go`, and to the aws-siem Terraform module,
   in one change. The lane name is the key prefix contract
   (`docs/contracts/lane-names.md` in aws-siem).
5. Write a `.tests.yml` from a **real** record out of the filtered bucket --
   not from the rule. A test written from the rule proves only that the rule
   matches itself. TrailAlerts' fixtures are a good starting shape for
   CloudTrail.
