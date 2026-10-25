# Detection rules

**96 rules across 11 log sources.**

> Generated from the rules tree by `make docs`. Do not edit by hand —
> `TestRules_CatalogIsUpToDate` fails if this file and the rules disagree.

## How to read an alert

An alert arrives as one `detection.alert.v1` message on the shared
`detections-alerts` queue, carrying the rule that fired, the record that
fired it, and where that record came from:

```json
{"schema_version":"detection.alert.v1","id":"det_…","alerted_at":"…",
 "log_source":"aws",
 "rule":{"id":"…","title":"…","level":"high","tags":[…],"file":"aws/….yml"},
 "provenance":{"bucket":"filtered-…","key":"aws/date=…/….ndjson.gz",
               "event_index":0,"sqs_message_id":"…"},
 "event":{…the record as Vector wrote it…},"event_sha256":"…"}
```

Three things worth knowing when triaging:

- **`rule.id` is the join key back to this page.** Find the rule below by
  its id to get the description, the false positives and the exact match
  condition.
- **`id` is content-derived**, from the rule id plus the object key and
  the record's index within it — never the clock. The same detection redelivered
  produces a byte-identical id, so duplicates are duplicates and consumers
  upsert on it.
- **`provenance` locates the original record**, so you can pull the
  surrounding events out of the filtered bucket for context.

## What these rules cannot do

Matching is **stateless and single-event**: each record is evaluated on its own.
Aggregations, `timeframe` and correlation rules are rejected when the
ruleset loads, rather than silently half-working.

So there are no brute-force, rate-spike or impossible-travel detections here,
and there cannot be until the engine keeps cross-event state. Anything of that
shape has to be expressed as a single record — usually by having the producer
compute the fact and emit it.

Wildcards also do not work in a value: `*` is matched literally. See
`rules/README.md`.

## Coverage

| Log source | 🔴 critical | 🟠 high | 🟡 medium | 🔵 low | ⚪ informational | **Total** |
|---|---:|---:|---:|---:|---:|---:|
| [`alb`](#alb) | – | 1 | – | – | – | **1** |
| [`aws`](#aws) | 1 | 22 | 12 | 12 | – | **47** |
| [`cloudflare`](#cloudflare) | – | 1 | 1 | – | – | **2** |
| [`dns`](#dns) | – | – | 2 | – | – | **2** |
| [`gcp`](#gcp) | 1 | 1 | – | 1 | – | **3** |
| [`github`](#github) | 1 | 2 | – | – | – | **3** |
| [`k8s`](#k8s) | 8 | 11 | 5 | 3 | – | **27** |
| [`onepassword`](#onepassword) | – | 2 | 1 | – | – | **3** |
| [`scanner`](#scanner) | – | 3 | 1 | – | – | **4** |
| [`slack`](#slack) | – | – | 2 | – | – | **2** |
| [`workspace`](#workspace) | 2 | – | – | – | – | **2** |
| **Total** | **13** | **43** | **24** | **16** | **0** | **96** |

---

## alb

### 🟠 high — Load Balancer Negotiated Legacy TLS

`c41a9e57-3082-4db6-8f2a-6e7d05b93c18` · [`rules/alb/alb_legacy_tls_negotiated.yml`](../rules/alb/alb_legacy_tls_negotiated.yml) · 7 tests (3 firing)

> **Status: experimental.**

A client completed a TLS handshake with a load balancer using TLSv1, TLSv1.1, SSLv3 or SSLv2. Not an attempt -- a negotiated connection, which means the listener's security policy still permits it. Measured across a full day of the ALB connection lane, the current count is zero: every connection negotiates TLSv1.2 or TLSv1.3. That makes this a sentinel rather than a monitor. It costs nothing while the estate stays correct, and it fires on the day a listener policy is loosened or a new load balancer is created from an old template. Written as an explicit list of bad versions rather than "not TLSv1.2 or 1.3", so a connection that carries no tls_protocol at all -- a plain HTTP listener, or a handshake that never completed -- cannot trip it.

**Fires when** `log_type` is `alb_connection` and `tls_protocol` is one of `TLSv1`, `TLSv1.1`, `SSLv3`, `SSLv2`

**Likely false positives**

- A deliberate exception for a legacy partner integration. If one exists it should be a listener with its own policy and its own documented owner, and that elb name belongs in a filter here rather than in this note.

**ATT&CK** attack.credential_access, attack.t1040

---

## aws

### 🔴 critical — SSO Elevator Grant Approved By Its Own Requester

`8d4b2e57-1f96-4a83-b5c0-6e7f8a9b0c12` · [`rules/aws/sso_self_approved_grant.yml`](../rules/aws/sso_self_approved_grant.yml) · 5 tests (2 firing)

> **Status: experimental.**

A just-in-time AWS access grant through the SSO Elevator was approved by the person who requested it. The Slack approval step is the only control between an engineer and a production AWS role, so an approval that closes its own loop does not weaken that control, it removes it. approval_kind is computed in Vector (the aws parser transform) because Sigma cannot compare two fields of one record -- sigma-go does not implement |fieldref -- so this detection exists there or not at all. Requires a Vector build that emits approval_kind. Without it the field is absent and this rule cannot fire.

**Fires when** (`feed` is `sso` and `approval_kind` is `self`) **and** `operation_type` is `grant`

**Likely false positives**

- A documented break-glass grant made while the elevator is configured to permit self-approval. Still worth reading every time.

**ATT&CK** attack.privilege_escalation, attack.t1078.004

- <https://github.com/fivexl/terraform-aws-sso-elevator>

### 🟠 high — AWS Account Left The Organization

`3e8a5d71-6b29-4f04-9c15-7d2e3f4a5b61` · [`rules/aws/organization_account_left.yml`](../rules/aws/organization_account_left.yml) · 4 tests (2 firing)

> **Status: experimental.**

An account left the AWS Organization. Leaving takes the account out of scope of every service control policy, every org-wide GuardDuty detector and the org CloudTrail that feeds this detection plane, all at once. It is both a governance event and the single cleanest way to remove an account from monitoring. Adapted from TrailAlerts (Apache-2.0).

**Fires when** (`eventSource` is `organizations.amazonaws.com` and `eventName` is one of `LeaveOrganization`, `RemoveAccountFromOrganization`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- A planned account decommission or tenant split. Rare enough that each one should be reconcilable against a change record.

**ATT&CK** attack.defense_evasion

- <https://github.com/adanalvarez/TrailAlerts>

### 🟠 high — AWS Config Recording Stopped Or Deleted

`7e3d90b5-2c41-4a86-9f07-8b1a2c3d4e56` · [`rules/aws/config_recorder_stopped_or_deleted.yml`](../rules/aws/config_recorder_stopped_or_deleted.yml) · 4 tests (2 firing)

> **Status: experimental.**

AWS Config recording was stopped, or a recorder or delivery channel was deleted. Config is the record of what the estate looked like and when it changed, so switching it off removes the evidence trail for everything that follows rather than any single action. It is a standard early step once an attacker has administrative access. Security Hub control CloudWatch.9 (CIS AWS Foundations 3.9 / 4.9).

**Fires when** (`eventSource` is `config.amazonaws.com` and `eventName` is one of `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel`, `PutConfigurationRecorder`, `PutDeliveryChannel`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform reconciling the Config recorder. PutConfigurationRecorder and PutDeliveryChannel are included because a recorder reconfigured to record nothing is equivalent to one stopped, and that is not visible from the event name alone -- expect these two to be the chatty half of this rule.

**ATT&CK** attack.defense_evasion, attack.t1562.008

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-9>

### 🟠 high — AWS Console Sign-In Without MFA

`4f92a1c7-6d38-4b05-9e74-2a3b5c6d7e81` · [`rules/aws/console_login_without_mfa.yml`](../rules/aws/console_login_without_mfa.yml) · 4 tests (1 firing)

> **Status: experimental.**

A successful console sign-in where multi-factor authentication was not used. Access to this estate is federated through Google Workspace and the SSO Elevator, so an interactive console login with a password and no second factor is not how anyone is supposed to get in. It is the shape of a credential that has been reused or stolen. Security Hub control CloudWatch.3 (CIS AWS Foundations 3.2 / 4.2). SAML and role-federated sign-ins are excluded: they carry MFA at the identity provider and record MFAUsed as "No" regardless, so including them would make this rule fire on every normal login.

**Fires when** (`eventSource` is `signin.amazonaws.com` and `eventName` is `ConsoleLogin` and `responseElements.ConsoleLogin` is `Success`) **and** `additionalEventData.MFAUsed` is `No` **and not** `userIdentity.type` is one of `AssumedRole`, `FederatedUser`

**Likely false positives**

- A break-glass root sign-in, which should be rare and is separately covered at critical by root_activity_in_management_account.

**ATT&CK** attack.initial_access, attack.t1078.004

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-3>

### 🟠 high — AWS EC2 Startup Shell Script Change

`1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df` · [`rules/aws/ec2_startup_script_change.yml`](../rules/aws/ec2_startup_script_change.yml) · 2 tests (1 firing)

> **Status: test.**

Detects changes to the EC2 instance startup script. The shell script will be executed as root/SYSTEM every time the specific instances are booted up.

**Fires when** `eventSource` is `ec2.amazonaws.com` and `requestParameters.attribute` is `userData` and `eventName` is `ModifyInstanceAttribute`

**Likely false positives**

- Valid changes to the startup script

**ATT&CK** attack.execution, attack.t1059.001, attack.t1059.003, attack.t1059.004

- <https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ec2__startup_shell_script/main.py#L9>

### 🟠 high — AWS GuardDuty Important Change

`6e61ee20-ce00-4f8d-8aee-bedd8216f7e3` · [`rules/aws/guardduty_disruption.yml`](../rules/aws/guardduty_disruption.yml) · 2 tests (1 firing)

> **Status: test.**

Detects updates of the GuardDuty list of trusted IPs, perhaps to disable security alerts against malicious IPs.

**Fires when** `eventSource` is `guardduty.amazonaws.com` and `eventName` is `CreateIPSet`

**Likely false positives**

- Valid change in the GuardDuty (e.g. to ignore internal scanners)

**ATT&CK** attack.defense-impairment, attack.t1685

- <https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/guardduty__whitelist_ip/main.py#L9>

### 🟠 high — AWS IAM Administrator Policy Attached Or Inline Policy Written

`2d8f4a61-5e93-4c07-b12a-6f7e8d9c0a1b` · [`rules/aws/iam_admin_policy_attached.yml`](../rules/aws/iam_admin_policy_attached.yml) · 6 tests (3 firing)

> **Status: experimental.**

An administrator-grade managed policy was attached to a user, role or group, or an inline policy was written directly onto one. Both are durable privilege grants that survive the session, unlike an SSO Elevator grant which expires. Security Hub control CloudWatch.4 (CIS 3.4 / 4.4) asks for an alarm on all sixteen IAM policy change events. That is narrowed here to the administrator-granting subset and to inline policies, because in a Terraform-managed estate the full set fires on routine deploys. The rest of the control is recorded as partially covered rather than quietly claimed. Inline policies are included at the same level as admin attachment despite granting less on average: they are how privilege is added without touching a reviewed, named policy document.

**Fires when** (((`eventSource` is `iam.amazonaws.com` and `eventName` is one of `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`) **and** `requestParameters.policyArn` contains any of `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`) **or** (`eventSource` is `iam.amazonaws.com` and `eventName` is one of `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`)) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform provisioning a new administrative role. Attributable via userIdentity.sessionContext.sessionIssuer.

**ATT&CK** attack.privilege_escalation, attack.persistence, attack.t1098.003

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-4>

### 🟠 high — AWS IAM S3Browser LoginProfile Creation

`db014773-b1d3-46bd-ba26-133337c0ffee` · [`rules/aws/iam_s3browser_loginprofile_creation.yml`](../rules/aws/iam_s3browser_loginprofile_creation.yml) · 3 tests (2 firing)

> **Status: test.**

Detects S3 Browser utility performing reconnaissance looking for existing IAM Users without a LoginProfile defined then (when found) creating a LoginProfile.

**Fires when** `eventSource` is `iam.amazonaws.com` and `eventName` is one of `GetLoginProfile`, `CreateLoginProfile` and `userAgent` contains `S3 Browser`

**Likely false positives**

- Valid usage of S3 Browser for IAM LoginProfile listing and/or creation

**ATT&CK** attack.execution, attack.persistence, attack.initial-access, attack.privilege-escalation, attack.stealth, attack.t1059.009, attack.t1078.004

- <https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor>

### 🟠 high — AWS IAM S3Browser User or AccessKey Creation

`db014773-d9d9-4792-91e5-133337c0ffee` · [`rules/aws/iam_s3browser_user_or_accesskey_creation.yml`](../rules/aws/iam_s3browser_user_or_accesskey_creation.yml) · 3 tests (2 firing)

> **Status: test.**

Detects S3 Browser utility creating IAM User or AccessKey.

**Fires when** `eventSource` is `iam.amazonaws.com` and `eventName` is one of `CreateUser`, `CreateAccessKey` and `userAgent` contains `S3 Browser`

**Likely false positives**

- Valid usage of S3 Browser for IAM User and/or AccessKey creation

**ATT&CK** attack.privilege-escalation, attack.execution, attack.persistence, attack.initial-access, attack.stealth, attack.t1059.009, attack.t1078.004

- <https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor>

### 🟠 high — AWS Identity Center Identity Provider Change

`d3adb3ef-b7e7-4003-9092-1924c797db35` · [`rules/aws/sso_idp_change.yml`](../rules/aws/sso_idp_change.yml) · 2 tests (1 firing)

> **Status: test.**

Detects a change in the AWS Identity Center (FKA AWS SSO) identity provider. A change in identity provider allows an attacker to establish persistent access or escalate privileges via user impersonation.

**Fires when** `eventSource` is one of `sso-directory.amazonaws.com`, `sso.amazonaws.com` and `eventName` is one of `AssociateDirectory`, `DisableExternalIdPConfigurationForDirectory`, `DisassociateDirectory`, `EnableExternalIdPConfigurationForDirectory`

**Likely false positives**

- Authorized changes to the AWS account's identity provider

**ATT&CK** attack.persistence, attack.credential-access, attack.defense-impairment, attack.t1556

- <https://docs.aws.amazon.com/singlesignon/latest/userguide/app-enablement.html>
- <https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html>
- <https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycentersuccessortoawssinglesign-on.html>

### 🟠 high — AWS Identity Center Permission Set Definition Changed

`e70b4d19-8c53-4a26-9f84-1d5e6a7b8c92` · [`rules/aws/identity_center_permission_set_changed.yml`](../rules/aws/identity_center_permission_set_changed.yml) · 6 tests (3 firing)

> **Status: experimental.**

The definition of an IAM Identity Center permission set was created, altered or deleted -- an inline policy written, a managed policy attached, a permissions boundary changed. This edits what the permission set grants, so it silently changes the access of everyone who can already assume it, including through the SSO Elevator, without any new grant being requested or approved. Deliberately scoped to permission set *definitions* rather than account assignments. The SSO Elevator works by creating and deleting assignments and never touches a definition, so this rule needs no allowlist of automation roles to stay quiet -- and an allowlist that drifts is how a rule like this stops working without anyone noticing.

**Fires when** (`eventSource` is `sso.amazonaws.com` and `eventName` is one of `CreatePermissionSet`, `UpdatePermissionSet`, `DeletePermissionSet`, `PutInlinePolicyToPermissionSet`, `DeleteInlinePolicyFromPermissionSet`, `AttachManagedPolicyToPermissionSet`, `DetachManagedPolicyFromPermissionSet`, `AttachCustomerManagedPolicyReferenceToPermissionSet`, `DetachCustomerManagedPolicyReferenceFromPermissionSet`, `PutPermissionsBoundaryToPermissionSet`, `DeletePermissionsBoundaryFromPermissionSet`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform managing permission sets as code. These should be rare, tied to a reviewed change, and attributable to the CI role in userIdentity.sessionContext.sessionIssuer -- if they turn out to be frequent, narrow this on that field rather than lowering the level.

**ATT&CK** attack.persistence, attack.privilege_escalation, attack.t1098.003

- <https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html>
- <https://github.com/fivexl/terraform-aws-sso-elevator>

### 🟠 high — AWS KMS Key Disabled Or Scheduled For Deletion

`1a6c8e42-3b57-4d90-ae21-5c7f9b0d2e34` · [`rules/aws/kms_key_disabled_or_scheduled_for_deletion.yml`](../rules/aws/kms_key_disabled_or_scheduled_for_deletion.yml) · 4 tests (2 firing)

> **Status: experimental.**

A customer managed KMS key was disabled or scheduled for deletion. Everything encrypted under that key becomes unreadable when the deletion completes, including data the owner of the key did not know about, so this is both a destructive action and a way to deny access to evidence. The pending window is the only chance to cancel. Security Hub control CloudWatch.7 (CIS AWS Foundations 3.7 / 4.7).

**Fires when** (`eventSource` is `kms.amazonaws.com` and `eventName` is one of `DisableKey`, `ScheduleKeyDeletion`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Decommissioning a key as part of a planned teardown. Should be reconcilable against a change record, and the deletion window makes that check possible.

**ATT&CK** attack.impact, attack.t1485

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-7>

### 🟠 high — AWS Root Account Used

`2c9e5f81-4b7a-4d62-8e13-9a0b1c2d3e4f` · [`rules/aws/root_account_activity.yml`](../rules/aws/root_account_activity.yml) · 4 tests (2 firing)

The root account performed an API call. Root should be used for nothing except the handful of tasks that require it, so any activity is worth a look, and console logins especially.

**Fires when** `userIdentity.type` is `Root` **and not** `eventType` is `AwsServiceEvent`

**Likely false positives**

- Account setup and billing tasks that genuinely require root.

**ATT&CK** attack.privilege_escalation, attack.t1078.004

- <https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html>

### 🟠 high — AWS Route 53 Resolver Query Logging Deleted

`7c2f9b40-3d85-4a17-b6e2-8f0a1b2c3d4e` · [`rules/aws/dns_query_logging_deleted.yml`](../rules/aws/dns_query_logging_deleted.yml) · 4 tests (2 firing)

> **Status: experimental.**

A Route 53 Resolver query log configuration was deleted or disassociated. This estate ships resolver query logs into the archive, so they are a live detection source rather than a dormant setting, and DNS is where command-and-control and exfiltration are most visible after the fact. Adapted from TrailAlerts (Apache-2.0).

**Fires when** (`eventSource` is `route53resolver.amazonaws.com` and `eventName` is one of `DeleteResolverQueryLogConfig`, `DisassociateResolverQueryLogConfig`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Decommissioning a VPC that had query logging attached.

**ATT&CK** attack.defense_evasion, attack.t1562.008

- <https://github.com/adanalvarez/TrailAlerts>

### 🟠 high — AWS Security Group Ingress Opened To The Internet

`8b5e7d03-9a26-4c41-b8f5-1e2d3a4b5c67` · [`rules/aws/security_group_opened_to_the_internet.yml`](../rules/aws/security_group_opened_to_the_internet.yml) · 5 tests (3 firing)

> **Status: experimental.**

An ingress rule was authorized from 0.0.0.0/0 or ::/0, opening a port to the whole internet. Security Hub control CloudWatch.10 (CIS 3.10 / 4.10) asks for an alarm on every security group change. That is deliberately narrowed here to the case that is actually dangerous: in an estate where security groups are managed by Terraform, alerting on all six change events would fire on routine infrastructure deploys and be muted within a fortnight, which is worse coverage than a rule people still read. The broader control is recorded as partially covered rather than quietly claimed.

**Fires when** (`eventSource` is `ec2.amazonaws.com` and `eventName` is `AuthorizeSecurityGroupIngress`) **and** (`requestParameters.ipPermissions.items.ipRanges.items.cidrIp` is `0.0.0.0/0` **or** `requestParameters.ipPermissions.items.ipv6Ranges.items.cidrIpv6` is `::/0`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- A deliberately public listener, typically in front of a load balancer. These should be few and known.

**ATT&CK** attack.initial_access, attack.t1190

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-10>

### 🟠 high — AWS SecurityHub Findings Evasion

`a607e1fe-74bf-4440-a3ec-b059b9103157` · [`rules/aws/securityhub_finding_evasion.yml`](../rules/aws/securityhub_finding_evasion.yml) · 2 tests (1 firing)

Detects the modification of the findings on SecurityHub.

**Fires when** `eventSource` is `securityhub.amazonaws.com` and `eventName` is one of `BatchUpdateFindings`, `DeleteInsight`, `UpdateFindings`, `UpdateInsight`

**Likely false positives**

- System or Network administrator behaviors
- DEV, UAT, SAT environment. You should apply this rule with PROD environment only.

**ATT&CK** attack.defense-impairment, attack.t1685

- <https://docs.aws.amazon.com/cli/latest/reference/securityhub/>

### 🟠 high — AWS Short Expiry Lifecycle Rule Applied To A Bucket

`0d5b8e93-4c17-42a6-b8f1-9e0a1b2c3d4f` · [`rules/aws/log_bucket_lifecycle_shortened.yml`](../rules/aws/log_bucket_lifecycle_shortened.yml) · 4 tests (2 firing)

> **Status: experimental.**

A lifecycle configuration was applied that expires objects within a week. Lifecycle expiry deletes logs on a schedule with no further API calls, so it destroys evidence quietly and in a way that looks like configuration rather than deletion. Applied to a log or archive bucket it is an anti-forensics step; this estate keeps six years of raw archive precisely so that is not possible by accident. Adapted from TrailAlerts (Apache-2.0), which matched an expiry of exactly one day against a nested object literal. Rewritten as a numeric comparison so any short window is caught, and because matching a nested object literal is fragile here -- see the array note in sigma-config.yml.

**Fires when** (`eventSource` is `s3.amazonaws.com` and `eventName` is `PutBucketLifecycleConfiguration`) **and** `requestParameters.lifecycleConfiguration.rules.expiration.days` is at most `7` **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- A genuinely short-lived scratch bucket. Worth confirming the bucket name is not one of the archive or detection buckets.

**ATT&CK** attack.defense_evasion, attack.t1485

- <https://github.com/adanalvarez/TrailAlerts>

### 🟠 high — AWS VPC Flow Logs Deleted

`b1d47f26-9c58-4e30-a7b9-2c4d5e6f7a80` · [`rules/aws/vpc_flow_logs_deleted.yml`](../rules/aws/vpc_flow_logs_deleted.yml) · 3 tests (1 firing)

> **Status: experimental.**

A VPC flow log configuration was deleted. Flow logs are this estate's only record of network movement inside a VPC, and they feed the detection plane through Filebeat, so deleting one removes the evidence for everything that happens on that network afterwards rather than any single action. Adapted from TrailAlerts (Apache-2.0).

**Fires when** (`eventSource` is `ec2.amazonaws.com` and `eventName` is `DeleteFlowLogs`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Decommissioning a VPC. The flow log deletion should be accompanied by the VPC deletion itself, which vpc_changed records.

**ATT&CK** attack.defense_evasion, attack.t1562.008

- <https://github.com/adanalvarez/TrailAlerts>

### 🟠 high — CloudTrail Logging Disabled

`7f8b1c42-9d3e-4a51-b6c7-1e2f3a4b5c6d` · [`rules/aws/cloudtrail_logging_disabled.yml`](../rules/aws/cloudtrail_logging_disabled.yml) · 4 tests (2 firing)

A CloudTrail trail was stopped, deleted, or reconfigured. This is the first thing an attacker with console access does, because it blinds every other rule in this ruleset.

**Fires when** `eventSource` is `cloudtrail.amazonaws.com` and `eventName` is one of `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`

**Likely false positives**

- Terraform or CloudFormation reconfiguring a trail during a planned change.

**ATT&CK** attack.defense_evasion, attack.t1562.008

- <https://attack.mitre.org/techniques/T1562/008/>

### 🟠 high — Modification or Deletion of an AWS RDS Cluster

`457cc9ac-d8e6-4d1d-8c0e-251d0f11a74c` · [`rules/aws/rds_dbcluster_actions.yml`](../rules/aws/rds_dbcluster_actions.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects modifications to an RDS cluster or its deletion, which may indicate potential data exfiltration attempts, unauthorized access, or exposure of sensitive information.

**Fires when** `eventSource` is `rds.amazonaws.com` and `eventName` is one of `ModifyDBCluster`, `DeleteDBCluster`

**Likely false positives**

- Verify if the modification or deletion was performed by an authorized administrator.
- Confirm if the modification or deletion was part of a planned change or maintenance activity.

**ATT&CK** attack.exfiltration, attack.t1020

- <https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html>
- <https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html>
- <https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance>

### 🟠 high — Restore Public AWS RDS Instance

`c3f265c7-ff03-4056-8ab2-d486227b4599` · [`rules/aws/rds_public_db_restore.yml`](../rules/aws/rds_public_db_restore.yml) · 2 tests (1 firing)

> **Status: test.**

Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.

**Fires when** `eventSource` is `rds.amazonaws.com` and `responseElements.publiclyAccessible` is `true` and `eventName` is `RestoreDBInstanceFromDBSnapshot`

**Likely false positives**

- Unknown

**ATT&CK** attack.exfiltration, attack.t1020

- <https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py>

### 🟠 high — S3 Public Access Block Removed

`5a1d3c74-8e2b-4f19-a6d5-7b8c9d0e1f22` · [`rules/aws/s3_public_access_block_removed.yml`](../rules/aws/s3_public_access_block_removed.yml) · 3 tests (1 firing)

> **Status: experimental.**

A bucket's public access block was deleted, or its policy status changed. Every bucket in the log archive is created with a full public access block, so removing one is either a mistake or an exfiltration setup.

**Fires when** (`eventSource` is `s3.amazonaws.com` and `eventName` is one of `DeleteBucketPublicAccessBlock`, `PutPublicAccessBlock`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- A deliberate change to a bucket fronting a public website.

**ATT&CK** attack.exfiltration

### 🟠 high — SSO Elevator Grant With No Approver Recorded

`4f9c6a23-8e51-4d07-9b34-2a5b6c7d8e90` · [`rules/aws/sso_grant_without_approver.yml`](../rules/aws/sso_grant_without_approver.yml) · 3 tests (1 firing)

> **Status: experimental.**

An access grant went out with no approver recorded at all. Whatever produced it, the approval step did not happen, which is a weaker position than a self-approval: there is not even a name to ask about. Companion to sso_self_approved_grant. Both depend on approval_kind, computed in Vector because Sigma cannot compare two fields.

**Fires when** `feed` is `sso` and `approval_kind` is `none` and `operation_type` is `grant`

**Likely false positives**

- An elevator configuration that auto-approves a low-risk permission set. Worth confirming that is intended, and which sets it covers.

**ATT&CK** attack.privilege_escalation

- <https://github.com/fivexl/terraform-aws-sso-elevator>

### 🟡 medium — AWS EC2 Disable EBS Encryption

`16124c2d-e40b-4fcc-8f2c-5ab7870a2223` · [`rules/aws/ec2_disable_encryption.yml`](../rules/aws/ec2_disable_encryption.yml) · 2 tests (1 firing)

Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region. Disabling default encryption does not change the encryption status of your existing volumes.

**Fires when** `eventSource` is `ec2.amazonaws.com` and `eventName` is `DisableEbsEncryptionByDefault`

**Likely false positives**

- System Administrator Activities
- DEV, UAT, SAT environment. You should apply this rule with PROD account only.

**ATT&CK** attack.impact, attack.t1486, attack.t1565

- <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html>

### 🟡 medium — AWS EFS Fileshare Modified or Deleted

`25cb1ba1-8a19-4a23-a198-d252664c8cef` · [`rules/aws/efs_fileshare_modified_or_deleted.yml`](../rules/aws/efs_fileshare_modified_or_deleted.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when a EFS Fileshare is modified or deleted. You can't delete a file system that is in use. If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.

**Fires when** `eventSource` is `elasticfilesystem.amazonaws.com` and `eventName` is `DeleteFileSystem`

**Likely false positives**

- Unknown

**ATT&CK** attack.impact

- <https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html>

### 🟡 medium — AWS EFS Fileshare Mount Modified or Deleted

`6a7ba45c-63d8-473e-9736-2eaabff79964` · [`rules/aws/efs_fileshare_mount_modified_or_deleted.yml`](../rules/aws/efs_fileshare_mount_modified_or_deleted.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when a EFS Fileshare Mount is modified or deleted. An adversary breaking any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts.

**Fires when** `eventSource` is `elasticfilesystem.amazonaws.com` and `eventName` is `DeleteMountTarget`

**Likely false positives**

- Unknown

**ATT&CK** attack.impact, attack.t1485

- <https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html>

### 🟡 medium — AWS Key Pair Import Activity

`92f84194-8d9a-4ee0-8699-c30bfac59780` · [`rules/aws/ec2_import_key_pair_activity.yml`](../rules/aws/ec2_import_key_pair_activity.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects the import of SSH key pairs into AWS EC2, which may indicate an attacker attempting to gain unauthorized access to instances. This activity could lead to initial access, persistence, or privilege escalation, potentially compromising sensitive data and operations.

**Fires when** `eventSource` is `ec2.amazonaws.com` and `eventName` is `ImportKeyPair`

**Likely false positives**

- Legitimate administrative actions by authorized users importing keys for valid purposes.
- Automated processes for infrastructure setup may trigger this alert.
- Verify the user identity, user agent, and source IP address to ensure they are expected.

**ATT&CK** attack.initial-access, attack.stealth, attack.t1078, attack.persistence, attack.privilege-escalation

- <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ImportKeyPair.html>

### 🟡 medium — AWS S3 Bucket Policy Or ACL Changed

`0c6d2f89-4b17-4e35-a8c9-3d5e6f7a8b90` · [`rules/aws/s3_bucket_policy_changed.yml`](../rules/aws/s3_bucket_policy_changed.yml) · 4 tests (2 firing)

> **Status: experimental.**

A bucket policy, ACL or CORS configuration was written or deleted. These are the controls that decide who can read a bucket, and this estate's buckets hold claims and log data, so a change here is a change to the blast radius of everything stored in them. Security Hub control CloudWatch.8 (CIS 3.8 / 4.8). Complements s3_public_access_block_removed, which covers the account and bucket level public-access block rather than the policy itself.

**Fires when** (`eventSource` is `s3.amazonaws.com` and `eventName` is one of `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, `PutBucketCors`, `DeleteBucketCors`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform applying bucket policy as code.
- Log delivery services writing their own bucket policy on setup.

**ATT&CK** attack.collection, attack.exfiltration, attack.t1530

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-8>

### 🟡 medium — AWS S3 Bucket Versioning Disable

`a136ac98-b2bc-4189-a14d-f0d0388e57a7` · [`rules/aws/disable_bucket_versioning.yml`](../rules/aws/disable_bucket_versioning.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when S3 bucket versioning is disabled. Threat actors use this technique during AWS ransomware incidents prior to deleting S3 objects.

**Fires when** `eventSource` is `s3.amazonaws.com` and `eventName` is `PutBucketVersioning` and `requestParameters` contains `Suspended`

**Likely false positives**

- AWS administrator legitimately disabling bucket versioning

**ATT&CK** attack.impact, attack.t1490

- <https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82>

### 🟡 medium — AWS Snapshot Backup Exfiltration

`abae8fec-57bd-4f87-aff6-6e3db989843d` · [`rules/aws/snapshot_backup_exfiltration.yml`](../rules/aws/snapshot_backup_exfiltration.yml) · 2 tests (1 firing)

> **Status: test.**

Detects the modification of an EC2 snapshot's permissions to enable access from another account

**Fires when** `eventSource` is `ec2.amazonaws.com` and `eventName` is `ModifySnapshotAttribute`

**Likely false positives**

- Valid change to a snapshot's permissions

**ATT&CK** attack.exfiltration, attack.t1537

- <https://www.justice.gov/file/1080281/download>

### 🟡 medium — AWS Suspicious SAML Activity

`f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e` · [`rules/aws/susp_saml_activity.yml`](../rules/aws/susp_saml_activity.yml) · 3 tests (2 firing)

> **Status: test.**

Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.

**Fires when** (`eventSource` is `iam.amazonaws.com` and `eventName` is `UpdateSAMLProvider`) **or** (`eventSource` is `sts.amazonaws.com` and `eventName` is `AssumeRoleWithSAML`)

**Likely false positives**

- Automated processes that uses Terraform may lead to false positives.
- SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
- SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.initial-access, attack.lateral-movement, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1078, attack.t1548, attack.t1550, attack.t1550.001

- <https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html>
- <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html>

### 🟡 medium — LoadBalancer Security Group Modification

`7a4409fc-f8ca-45f6-8006-127d779eaad9` · [`rules/aws/cloudtrail_security_group_change_loadbalancer.yml`](../rules/aws/cloudtrail_security_group_change_loadbalancer.yml) · 2 tests (1 firing)

> **Status: test.**

Detects changes to the security groups associated with an Elastic Load Balancer (ELB) or Application Load Balancer (ALB). This can indicate that a misconfiguration allowing more traffic into the system than required, or could indicate that an attacker is attempting to enable new connections into a VPC or subnet controlled by the account.

**Fires when** `eventSource` is `elasticloadbalancing.amazonaws.com` and `eventName` is one of `ApplySecurityGroupsToLoadBalancer`, `SetSecurityGroups`

**Likely false positives**

- Repurposing of an ELB or ALB to serve a different or additional application
- Changes to security groups to allow for new services to be deployed

**ATT&CK** attack.initial-access, attack.t1190

- <https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/>

### 🟡 medium — New AWS Lambda Function URL Configuration Created

`ec541962-c05a-4420-b9ea-84de072d18f4` · [`rules/aws/lambda_function_url.yml`](../rules/aws/lambda_function_url.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects when a user creates a Lambda function URL configuration, which could be used to expose the function to the internet and potentially allow unauthorized access to the function's IAM role for AWS API calls. This could give an adversary access to the privileges associated with the Lambda service role that is attached to that function.

**Fires when** `eventSource` is `lambda.amazonaws.com` and `eventName` is `CreateFunctionUrlConfig`

**Likely false positives**

- Creating a Lambda function URL configuration may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
- Creating a Lambda function URL configuration from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.initial-access, attack.privilege-escalation

- <https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunctionUrlConfig.html>
- <https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-lambda-privesc>
- <https://www.wiz.io/blog/how-to-set-secure-defaults-on-aws>

### 🟡 medium — RDS Database Security Group Modification

`14f3f1c8-02d5-43a2-a191-91ffb52d3015` · [`rules/aws/cloudtrail_security_group_change_rds.yml`](../rules/aws/cloudtrail_security_group_change_rds.yml) · 2 tests (1 firing)

> **Status: test.**

Detects changes to the security group entries for RDS databases. This can indicate that a misconfiguration has occurred which potentially exposes the database to the public internet, a wider audience within the VPC or that removal of valid rules has occurred which could impact the availability of the database to legitimate services and users.

**Fires when** `eventSource` is `rds.amazonaws.com` and `eventName` is one of `AuthorizeDBSecurityGroupIngress`, `CreateDBSecurityGroup`, `DeleteDBSecurityGroup`, `RevokeDBSecurityGroupIngress`

**Likely false positives**

- Creation of a new Database that needs new security group rules

**ATT&CK** attack.initial-access, attack.t1190

- <https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/>

### 🟡 medium — SES Identity Has Been Deleted

`20f754db-d025-4a8f-9d74-e0037e999a9a` · [`rules/aws/delete_identity.yml`](../rules/aws/delete_identity.yml) · 2 tests (1 firing)

> **Status: test.**

Detects an instance of an SES identity being deleted via the "DeleteIdentity" event. This may be an indicator of an adversary removing the account that carried out suspicious or malicious activities

**Fires when** `eventSource` is `ses.amazonaws.com` and `eventName` is `DeleteIdentity`

**Likely false positives**

- Unknown

**ATT&CK** attack.stealth, attack.t1070

- <https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/>

### 🔵 low — AWS EKS Cluster Created or Deleted

`33d50d03-20ec-4b74-a74e-1e65a38af1c0` · [`rules/aws/eks_cluster_created_or_deleted.yml`](../rules/aws/eks_cluster_created_or_deleted.yml) · 2 tests (1 firing)

> **Status: test.**

Identifies when an EKS cluster is created or deleted.

**Fires when** `eventSource` is `eks.amazonaws.com` and `eventName` is one of `CreateCluster`, `DeleteCluster`

**Likely false positives**

- EKS Cluster being created or deleted may be performed by a system administrator.
- Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
- EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.impact, attack.t1485

- <https://any-api.com/amazonaws_com/eks/docs/API_Description>

### 🔵 low — AWS ElastiCache Security Group Created

`4ae68615-866f-4304-b24b-ba048dfa5ca7` · [`rules/aws/elasticache_security_group_created.yml`](../rules/aws/elasticache_security_group_created.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when an ElastiCache security group has been created.

**Fires when** `eventSource` is `elasticache.amazonaws.com` and `eventName` is `CreateCacheSecurityGroup`

**Likely false positives**

- A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.persistence, attack.t1136, attack.t1136.003

- <https://github.com/elastic/detection-rules/blob/598f3d7e0a63221c0703ad9a0ea7e22e7bc5961e/rules/integrations/aws/persistence_elasticache_security_group_creation.toml>

### 🔵 low — AWS ElastiCache Security Group Modified or Deleted

`7c797da2-9cf2-4523-ba64-33b06339f0cc` · [`rules/aws/elasticache_security_group_modified_or_deleted.yml`](../rules/aws/elasticache_security_group_modified_or_deleted.yml) · 2 tests (1 firing)

> **Status: test.**

Identifies when an ElastiCache security group has been modified or deleted.

**Fires when** `eventSource` is `elasticache.amazonaws.com` and `eventName` is one of `DeleteCacheSecurityGroup`, `AuthorizeCacheSecurityGroupIngress`, `RevokeCacheSecurityGroupIngress`, `AuthorizeCacheSecurityGroupEgress`, `RevokeCacheSecurityGroupEgress`

**Likely false positives**

- A ElastiCache security group deletion may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security Group deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.impact, attack.t1531

- <https://github.com/elastic/detection-rules/blob/7d5efd68603f42be5e125b5a6a503b2ef3ac0f4e/rules/integrations/aws/impact_elasticache_security_group_modified_or_deleted.toml>

### 🔵 low — AWS Glue Development Endpoint Activity

`4990c2e3-f4b8-45e3-bc3c-30b14ff0ed26` · [`rules/aws/passed_role_to_glue_development_endpoint.yml`](../rules/aws/passed_role_to_glue_development_endpoint.yml) · 2 tests (1 firing)

> **Status: test.**

Detects possible suspicious glue development endpoint activity.

**Fires when** `eventSource` is `glue.amazonaws.com` and `eventName` is one of `CreateDevEndpoint`, `DeleteDevEndpoint`, `UpdateDevEndpoint`

**Likely false positives**

- Glue Development Endpoint Activity may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
- If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.privilege-escalation

- <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
- <https://docs.aws.amazon.com/glue/latest/webapi/API_CreateDevEndpoint.html>

### 🔵 low — AWS Network ACL Changed

`3c7a9e15-8b42-4d06-a97e-5f1c2d3e4a5b` · [`rules/aws/network_acl_changed.yml`](../rules/aws/network_acl_changed.yml) · 3 tests (1 firing)

> **Status: experimental.**

A network ACL or one of its entries was created, deleted or replaced. NACLs are the subnet-level allow/deny boundary, so a change here can expose a subnet that security groups were assumed to protect. Security Hub control CloudWatch.11. Deliberately low. Every alert-destination route currently includes the same Slack channel regardless of level, so severity does not yet change who is disturbed -- it only records intent. These are a record of who changed the network and when, not something to page on, and they are classified that way now so that they land correctly once routing distinguishes levels.

**Fires when** (`eventSource` is `ec2.amazonaws.com` and `eventName` is one of `CreateNetworkAcl`, `CreateNetworkAclEntry`, `DeleteNetworkAcl`, `DeleteNetworkAclEntry`, `ReplaceNetworkAclEntry`, `ReplaceNetworkAclAssociation`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform managing network infrastructure. Expected to be the bulk of this rule's volume; it earns its place as a record of who changed the network and when, not as a page.

**ATT&CK** attack.defense_evasion

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-11>

### 🔵 low — AWS Network Gateway Changed

`6a2e8c37-1d94-4b58-8e03-7c9a0b1d2e3f` · [`rules/aws/network_gateway_changed.yml`](../rules/aws/network_gateway_changed.yml) · 3 tests (1 firing)

> **Status: experimental.**

An internet or customer gateway was created, deleted, attached or detached. Attaching an internet gateway is the step that gives a previously private subnet a route off the network. Security Hub control CloudWatch.12. Deliberately low. Every alert-destination route currently includes the same Slack channel regardless of level, so severity does not yet change who is disturbed -- it only records intent. These are a record of who changed the network and when, not something to page on, and they are classified that way now so that they land correctly once routing distinguishes levels.

**Fires when** (`eventSource` is `ec2.amazonaws.com` and `eventName` is one of `CreateCustomerGateway`, `DeleteCustomerGateway`, `AttachInternetGateway`, `CreateInternetGateway`, `DeleteInternetGateway`, `DetachInternetGateway`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform managing network infrastructure. Expected to be the bulk of this rule's volume; it earns its place as a record of who changed the network and when, not as a page.

**ATT&CK** attack.defense_evasion

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-12>

### 🔵 low — AWS Route 53 Domain Transfer Lock Disabled

`3940b5f1-3f46-44aa-b746-ebe615b879e0` · [`rules/aws/route_53_domain_transferred_lock_disabled.yml`](../rules/aws/route_53_domain_transferred_lock_disabled.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when a transfer lock was removed from a Route 53 domain. It is recommended to refrain from performing this action unless intending to transfer the domain to a different registrar.

**Fires when** `eventSource` is `route53.amazonaws.com` and `eventName` is `DisableDomainTransferLock`

**Likely false positives**

- A domain transfer lock may be disabled by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Activity from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.persistence, attack.privilege-escalation, attack.credential-access, attack.t1098

- <https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/integrations/aws/persistence_route_53_domain_transfer_lock_disabled.toml>
- <https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html>
- <https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html>

### 🔵 low — AWS Route 53 Domain Transferred to Another Account

`b056de1a-6e6e-4e40-a67e-97c9808cf41b` · [`rules/aws/route_53_domain_transferred_to_another_account.yml`](../rules/aws/route_53_domain_transferred_to_another_account.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when a request has been made to transfer a Route 53 domain to another AWS account.

**Fires when** `eventSource` is `route53.amazonaws.com` and `eventName` is `TransferDomainToAnotherAwsAccount`

**Likely false positives**

- A domain may be transferred to another AWS account by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Domain transfers from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.persistence, attack.credential-access, attack.privilege-escalation, attack.t1098

- <https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/integrations/aws/persistence_route_53_domain_transferred_to_another_account.toml>

### 🔵 low — AWS Route Table Changed

`9f4b1a68-7e25-4c93-b04d-8a1b2c3d4e5f` · [`rules/aws/route_table_changed.yml`](../rules/aws/route_table_changed.yml) · 3 tests (1 firing)

> **Status: experimental.**

A route or route table was created, replaced, deleted or disassociated. A single added route can send traffic to an attacker-controlled appliance while every security group and NACL stays exactly as reviewed. Security Hub control CloudWatch.13. Deliberately low. Every alert-destination route currently includes the same Slack channel regardless of level, so severity does not yet change who is disturbed -- it only records intent. These are a record of who changed the network and when, not something to page on, and they are classified that way now so that they land correctly once routing distinguishes levels.

**Fires when** (`eventSource` is `ec2.amazonaws.com` and `eventName` is one of `CreateRoute`, `CreateRouteTable`, `ReplaceRoute`, `ReplaceRouteTableAssociation`, `DeleteRouteTable`, `DeleteRoute`, `DisassociateRouteTable`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform managing network infrastructure. Expected to be the bulk of this rule's volume; it earns its place as a record of who changed the network and when, not as a page.

**ATT&CK** attack.defense_evasion

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-13>

### 🔵 low — AWS S3 Data Management Tampering

`78b3756a-7804-4ef7-8555-7b9024a02e2d` · [`rules/aws/s3_data_management_tampering.yml`](../rules/aws/s3_data_management_tampering.yml) · 2 tests (1 firing)

> **Status: test.**

Detects when a user tampers with S3 data management in Amazon Web Services.

**Fires when** `eventSource` is `s3.amazonaws.com` and `eventName` is one of `PutBucketLogging`, `PutBucketWebsite`, `PutEncryptionConfiguration`, `PutLifecycleConfiguration`, `PutReplicationConfiguration`, `ReplicateObject`, `RestoreObject`

**Likely false positives**

- A S3 configuration change may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. S3 configuration change from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.exfiltration, attack.t1537

- <https://github.com/elastic/detection-rules/pull/1145/files>
- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html>
- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html>
- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html>
- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html>
- <https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html>
- <https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html>

### 🔵 low — AWS STS GetSessionToken Misuse

`b45ab1d2-712f-4f01-a751-df3826969807` · [`rules/aws/sts_getsessiontoken_misuse.yml`](../rules/aws/sts_getsessiontoken_misuse.yml) · 2 tests (1 firing)

> **Status: test.**

Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.

**Fires when** `eventSource` is `sts.amazonaws.com` and `eventName` is `GetSessionToken` and `userIdentity.type` is `IAMUser`

**Likely false positives**

- GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.lateral-movement, attack.privilege-escalation, attack.t1548, attack.t1550, attack.t1550.001

- <https://github.com/elastic/detection-rules/pull/1213>
- <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html>

### 🔵 low — AWS VPC Changed

`5e9c3b74-2a86-4f10-9d27-6b8c9d0e1f2a` · [`rules/aws/vpc_changed.yml`](../rules/aws/vpc_changed.yml) · 3 tests (1 firing)

> **Status: experimental.**

A VPC or VPC peering connection was created, deleted or modified. Accepting a peering connection joins this network to another account's, which is a trust relationship that no firewall rule inside the VPC expresses. Security Hub control CloudWatch.14. Deliberately low. Every alert-destination route currently includes the same Slack channel regardless of level, so severity does not yet change who is disturbed -- it only records intent. These are a record of who changed the network and when, not something to page on, and they are classified that way now so that they land correctly once routing distinguishes levels.

**Fires when** (`eventSource` is `ec2.amazonaws.com` and `eventName` is one of `CreateVpc`, `DeleteVpc`, `ModifyVpcAttribute`, `AcceptVpcPeeringConnection`, `CreateVpcPeeringConnection`, `DeleteVpcPeeringConnection`, `RejectVpcPeeringConnection`) **and not** `errorCode` starts with `AccessDenied`

**Likely false positives**

- Terraform managing network infrastructure. Expected to be the bulk of this rule's volume; it earns its place as a record of who changed the network and when, not as a page.

**ATT&CK** attack.defense_evasion

- <https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html#cloudwatch-14>

---

## cloudflare

### 🟠 high — Cloudflare Access Application Or Policy Deleted

`9dfc6c12-9d82-44b0-be44-9d4b53c3a70e` · [`rules/cloudflare/access_app_or_policy_deleted.yml`](../rules/cloudflare/access_app_or_policy_deleted.yml) · 5 tests (2 firing)

> **Status: experimental.**

A Cloudflare Access application or policy was deleted. Access is the authentication layer in front of internal applications; deleting the application removes that layer entirely, and deleting a policy can leave an application reachable under a broader remaining policy. Either reads as removal of a control until someone confirms it was planned. As with every audit-feed rule here, resource.type is a list because Cloudflare does not publish the v1 enum.

**Fires when** `source` is `cloudflare` and `feed` is `audit` and `action.type` is `delete` and `action.result` is `true` and `resource.type` is one of `access_app`, `access_application`, `access_policy`, `access_reusable_policy`

**Likely false positives**

- Decommissioning an internal application, or consolidating per-app policies into a reusable one.

**ATT&CK** attack.defense_evasion, attack.t1562

- <https://developers.cloudflare.com/cloudflare-one/policies/access/>
- <https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/>

### 🟡 medium — Cloudflare API Token Created Or Rolled

`b84c8d54-6427-44b7-a421-fe2ae70ff684` · [`rules/cloudflare/api_token_created_or_rolled.yml`](../rules/cloudflare/api_token_created_or_rolled.yml) · 5 tests (2 firing)

> **Status: experimental.**

An API token was created, or its secret was rolled. A token is a standing, MFA-free credential with whatever scope it was given, and a new or re-issued secret is the usual way persistence is kept on a Cloudflare account after an interactive session is lost. Cloudflare does not publish an enum for the v1 audit log's resource.type and action.type, so both are lists of the spellings in use; extend them from a real record rather than loosening the match.

**Fires when** `source` is `cloudflare` and `feed` is `audit` and `action.result` is `true` and `action.type` is one of `create`, `roll`, `rotate` and `resource.type` is one of `api_token`, `account_api_token`, `user_api_token`

**Likely false positives**

- A CI system or Terraform rotating its own token on schedule.
- An engineer creating a scoped token for a new integration.

**ATT&CK** attack.persistence, attack.t1098.001

- <https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/>
- <https://developers.cloudflare.com/fundamentals/api/get-started/create-token/>

---

## dns

### 🟡 medium — DNS Query With An Overlong Label

`3f7b21c8-9d4e-4a63-b115-2c6e8f90a4d7` · [`rules/dns/dns_long_label_query.yml`](../rules/dns/dns_long_label_query.yml) · 10 tests (2 firing)

> **Status: experimental.**

A single DNS label of 40 or more characters from the alphabet base32 and base64 use. Names are not normally built that way: a label is a hostname fragment, and the long ones that do occur are machine-generated. This is the per-record shadow of DNS tunnelling. The real signal is volume -- one host emitting thousands of such queries to one parent domain -- and this engine is stateless and single-event, so that rule cannot be written here. What this catches is the shape of one carrier record, which is enough to point an investigation at a source address worth counting in Athena.

**Fires when** `query_name` matches the regular expression `^[A-Za-z0-9+/=_-]{40,}\.` **and not** `query_name` contains `.amazonaws.com`

**Likely false positives**

- Content delivery and anti-virus vendors encode cache keys and file hashes into hostnames, so a steady low rate against one vendor domain is normal. Check the parent domain before treating a hit as exfiltration.
- Some SaaS products use long per-tenant subdomains. These are stable over time, where tunnelling labels are unique per query.

**ATT&CK** attack.exfiltration, attack.t1048.003

### 🟡 medium — Host Resolving A Public DNS Or DoH Resolver

`8c05e6a2-71bd-4f38-9e47-5a3d2b8c1f60` · [`rules/dns/dns_public_resolver_lookup.yml`](../rules/dns/dns_public_resolver_lookup.yml) · 7 tests (3 firing)

> **Status: experimental.**

Something inside the VPC asked internal DNS for the address of a public resolver -- Google, Cloudflare, Quad9 or OpenDNS, including their DNS-over-HTTPS endpoints. Workloads have no reason to look these up. Resolution is handed to them by DHCP, and a process going out of its way to find a different resolver is usually about to stop using the one that is logged. That is the point: this query is visible, and everything the host resolves afterwards may not be. It is a precursor rather than a compromise, which is why it is medium and not high. A hit is worth pairing with the flow logs for the same source address.

**Fires when** `query_name` is one of `dns.google.`, `dns.google.com.`, `cloudflare-dns.com.`, `one.one.one.one.`, `dns.quad9.net.`, `dns9.quad9.net.`, `doh.opendns.com.`, `dns.nextdns.io.`, `mozilla.cloudflare-dns.com.`, `security.cloudflare-dns.com.`, `family.cloudflare-dns.com.`

**Likely false positives**

- A container image whose base layer ships a resolver health check. Confirm by whether the same source address queries on a fixed interval.
- Security tooling that deliberately tests external resolution. If that is running here, add its source address as a filter rather than dropping the rule.

**ATT&CK** attack.command_and_control, attack.t1572, attack.defense_evasion

---

## gcp

### 🔴 critical — GCP IAM Policy Granted To allUsers

`6f0c3d28-7b94-4e15-a3c6-8d9e0f1a2b3c` · [`rules/gcp/iam_policy_opened_to_public.yml`](../rules/gcp/iam_policy_opened_to_public.yml) · 3 tests (1 firing)

> **Status: experimental.**

An IAM policy was set with a binding to allUsers or allAuthenticatedUsers, which makes the resource reachable by anyone on the internet, or by anyone with any Google account. This is the single most common cause of a public bucket.

**Fires when** (`source` is `gcp` and `protoPayload.methodName` contains `SetIamPolicy`) **and** `protoPayload.request.policy.bindings.members` contains any of `allUsers`, `allAuthenticatedUsers`

**Likely false positives**

- A resource intended to be public, which should be rare enough to confirm.

**ATT&CK** attack.exfiltration

- <https://cloud.google.com/iam/docs/overview>

### 🟠 high — GCP Service Account Key Created

`1e6a8b93-4c25-4d78-9f01-5a6b7c8d9e0f` · [`rules/gcp/service_account_key_created.yml`](../rules/gcp/service_account_key_created.yml) · 3 tests (1 firing)

> **Status: experimental.**

A user-managed service account key was created. These are long-lived credentials that leave the perimeter in files and rarely get rotated, which is why Google's own guidance is to avoid them entirely in favour of workload identity federation.

**Fires when** `source` is `gcp` and `protoPayload.methodName` is `google.iam.admin.v1.CreateServiceAccountKey`

**Likely false positives**

- A documented break-glass credential.

**ATT&CK** attack.persistence, attack.credential_access

- <https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys>

### 🔵 low — Google Cloud Storage Buckets Enumeration

`e2feb918-4e77-4608-9697-990a1aaf74c3` · [`rules/gcp/gcp_bucket_enumeration.yml`](../rules/gcp/gcp_bucket_enumeration.yml) · 5 tests (2 firing)

> **Status: test.**

Detects when storage bucket is enumerated in Google Cloud.

**Fires when** `gcp.audit.method_name` is one of `storage.buckets.list`, `storage.buckets.listChannels`

**Likely false positives**

- Storage Buckets being enumerated may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
- Storage Buckets enumerated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**ATT&CK** attack.discovery

- <https://cloud.google.com/storage/docs/json_api/v1/buckets>

---

## github

### 🔴 critical — GitHub Repository Made Public

`9b4e7a13-6c25-4d80-91f3-2a3b4c5d6e70` · [`rules/github/repo_made_public.yml`](../rules/github/repo_made_public.yml) · 4 tests (1 firing)

A private repository was made public, or created public. In an org whose repositories are private by default this is either a mistake that needs reverting within minutes or a deliberate exfiltration.

**Fires when** `action` is one of `repo.access`, `repo.create` **and** `visibility` is `public`

**Likely false positives**

- An intentionally open-sourced repository.

**ATT&CK** attack.exfiltration

- <https://docs.github.com/en/organizations/keeping-your-organization-secure>

### 🟠 high — GitHub Branch Protection Weakened

`3d7f2b58-1a94-4e63-8c05-6d7e8f9a0b13` · [`rules/github/branch_protection_removed.yml`](../rules/github/branch_protection_removed.yml) · 3 tests (2 firing)

A protected branch rule was destroyed or its overrides changed. Removing protection on a default branch is the step that makes an unreviewed commit possible, so it usually precedes rather than accompanies the interesting activity.

**Fires when** `action` is one of `protected_branch.destroy`, `protected_branch.policy_override`, `protected_branch.update_allow_force_pushes_enforcement_level`, `protected_branch.update_allow_deletions_enforcement_level`, `repository_ruleset.destroy`

**Likely false positives**

- Repository archival or a deliberate ruleset migration.

**ATT&CK** attack.defense_evasion

### 🟠 high — GitHub Org Owner or Admin Granted

`6e0a9c37-2f81-4b54-97d6-8a9b0c1d2e34` · [`rules/github/org_member_privilege_change.yml`](../rules/github/org_member_privilege_change.yml) · 3 tests (2 firing)

A member was promoted to organization owner, or an outside collaborator was added with admin rights. Either grants control over every repository the org holds.

**Fires when** (`action` is `org.update_member` and `permission` is `admin`) **or** (`action` is one of `org.add_member`, `org.invite_member` and `permission` is `admin`)

**Likely false positives**

- Planned onboarding of a new platform administrator.

**ATT&CK** attack.persistence, attack.privilege_escalation

---

## k8s

### 🔴 critical — Kubernetes Admission Webhook Created Or Modified

`10946f6e-f74f-5fef-843d-c0d3e7188eb2` · [`rules/k8s/k8s_webhook_modified.yml`](../rules/k8s/k8s_webhook_modified.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation or modification of admission webhooks - can be used to intercept and mutate all cluster operations. Ported from samma-io/siem-rules rule k8s-webhook-modified.

**Fires when** `kind` is `Event` and `verb` is one of `create`, `update`, `patch` and `objectRef.resource` is one of `mutatingwebhookconfigurations`, `validatingwebhookconfigurations`

**Likely false positives**

- Installing or upgrading an operator that ships admission webhooks.

**ATT&CK** attack.t1525

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_webhook_modified.yaml>

### 🔴 critical — Kubernetes Anonymous API Request

`58d61fa9-a318-57d1-81d8-10296d50cfcb` · [`rules/k8s/k8s_anonymous_access.yml`](../rules/k8s/k8s_anonymous_access.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects anonymous or unauthenticated API requests which may indicate misconfigured RBAC or unauthorized access. Ported from samma-io/siem-rules rule k8s-anonymous-access.

**Fires when** `kind` is `Event` and `user.username` is `system:anonymous`

**Likely false positives**

- Health checks against /healthz, /livez or /readyz on a cluster that allows anonymous auth for them.

**ATT&CK** attack.t1078

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_anonymous_access.yaml>

### 🔴 critical — Kubernetes CoreDNS ConfigMap Modified

`094f90f0-5024-5852-9167-dabc93e54d87` · [`rules/k8s/k8s_coredns_modified.yml`](../rules/k8s/k8s_coredns_modified.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects modifications to the CoreDNS configmap - may indicate DNS poisoning for lateral movement. Ported from samma-io/siem-rules rule k8s-coredns-modified.

**Fires when** `kind` is `Event` and `objectRef.resource` is `configmaps` and `objectRef.name` is `coredns` and `objectRef.namespace` is `kube-system` and `verb` is one of `update`, `patch`

**Likely false positives**

- A planned CoreDNS configuration change or a cluster upgrade.

**ATT&CK** attack.t1557

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_coredns_modified.yaml>

### 🔴 critical — Kubernetes Events Deleted

`936f57ce-3685-5098-a580-6c4f215e870d` · [`rules/k8s/k8s_event_deleted.yml`](../rules/k8s/k8s_event_deleted.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects deletion of Kubernetes events - may indicate an attacker covering their tracks. Ported from samma-io/siem-rules rule k8s-event-deleted.

**Fires when** `kind` is `Event` and `objectRef.resource` is `events` and `verb` is one of `delete`, `deletecollection`

**Likely false positives**

- The API server's own event TTL garbage collection, if it is audited.

**ATT&CK** attack.t1070

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_event_deleted.yaml>

### 🔴 critical — Kubernetes Namespace Deleted

`35aab55a-b033-53c2-927c-930f6e15305e` · [`rules/k8s/k8s_namespace_deleted.yml`](../rules/k8s/k8s_namespace_deleted.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects deletion of Kubernetes namespaces - potential data destruction or service disruption. Ported from samma-io/siem-rules rule k8s-namespace-deleted.

**Fires when** `kind` is `Event` and `objectRef.resource` is `namespaces` and `verb` is `delete`

**Likely false positives**

- Tearing down an environment or a GitOps prune.

**ATT&CK** attack.t1485

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_namespace_deleted.yaml>

### 🔴 critical — Kubernetes Pod With Host Namespaces Created

`52e0a62e-b6fe-5996-bedd-b89746f5bf80` · [`rules/k8s/k8s_privileged_pod.yml`](../rules/k8s/k8s_privileged_pod.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation of pods with privileged security context or host namespace access - escape to host risk. Ported from samma-io/siem-rules rule k8s-privileged-pod.

**Fires when** (`kind` is `Event` and `objectRef.resource` is `pods` and `verb` is `create`) **and** (`requestObject.spec.hostNetwork` is `true` or `requestObject.spec.hostPID` is `true` or `requestObject.spec.hostIPC` is `true`)

**Likely false positives**

- Node agents (CNI, storage, monitoring) that need host namespaces.

**ATT&CK** attack.t1611, attack.t1610

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_privileged_pod.yaml>

### 🔴 critical — Kubernetes Role Binding Created

`bbfb67d5-6fba-565e-9660-d1bfa6ce2b21` · [`rules/k8s/k8s_clusterrole_binding_created.yml`](../rules/k8s/k8s_clusterrole_binding_created.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation of ClusterRoleBindings - may indicate privilege escalation especially if binding cluster-admin. Ported from samma-io/siem-rules rule k8s-clusterrole-binding-created.

**Fires when** `kind` is `Event` and `verb` is `create` and `objectRef.resource` is one of `clusterrolebindings`, `rolebindings`

**Likely false positives**

- Helm charts and operators installing their own RBAC.

**ATT&CK** attack.t1098.006, attack.t1078

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_clusterrole_binding_created.yaml>

### 🔴 critical — Kubernetes User Impersonation

`8c01fd33-a911-555a-bd5e-eb73625d05b0` · [`rules/k8s/k8s_impersonation.yml`](../rules/k8s/k8s_impersonation.yml) · 4 tests (2 firing)

> **Status: experimental.**

Detects an API request made while impersonating another identity (kubectl --as / --as-group, or the Impersonate-User header). The audit event of an impersonated request carries impersonatedUser, and user is the impersonator; there is no event with verb impersonate. A refused impersonation records no impersonatedUser: it is a 403, which k8s_forbidden_access covers. Ported from samma-io/siem-rules rule k8s-impersonation.

**Fires when** `kind` is `Event` **and not** `impersonatedUser.username` is `null`

**Likely false positives**

- Administrators testing RBAC with kubectl --as.
- Proxies that act for their users through impersonation (Rancher, Teleport, kube-oidc-proxy, Argo CD sync impersonation); every request they make fires.

**ATT&CK** attack.t1078

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_impersonation.yaml>

### 🟠 high — Kubernetes Attach To Running Container

`0868fa4d-a6b5-53f1-b5dd-de1149f810b0` · [`rules/k8s/k8s_pod_attach.yml`](../rules/k8s/k8s_pod_attach.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects attaching to a running container - indicates interactive access for lateral movement. Ported from samma-io/siem-rules rule k8s-pod-attach.

**Fires when** `kind` is `Event` and `objectRef.resource` is `pods` and `objectRef.subresource` is `attach` and `verb` is `create`

**Likely false positives**

- An operator debugging a container interactively.

**ATT&CK** attack.t1609

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_pod_attach.yaml>

### 🟠 high — Kubernetes Exec Into Pod

`247af81a-dd65-5cce-b412-6d7a5f98f861` · [`rules/k8s/k8s_pod_exec.yml`](../rules/k8s/k8s_pod_exec.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects command execution inside a running pod via kubectl exec - indicates lateral movement or container administration. Ported from samma-io/siem-rules rule k8s-pod-exec.

**Fires when** `kind` is `Event` and `objectRef.resource` is `pods` and `objectRef.subresource` is `exec` and `verb` is `create`

**Likely false positives**

- An operator debugging a container; tooling that execs for health checks.

**ATT&CK** attack.t1609

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_pod_exec.yaml>

### 🟠 high — Kubernetes NetworkPolicy Changed

`ec8657f8-a27f-5d47-96e4-76b192c1f7cd` · [`rules/k8s/k8s_network_policy_changed.yml`](../rules/k8s/k8s_network_policy_changed.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation, modification, or deletion of network policies - may weaken network segmentation. Ported from samma-io/siem-rules rule k8s-network-policy-changed.

**Fires when** `kind` is `Event` and `objectRef.resource` is `networkpolicies` and `verb` is one of `create`, `update`, `patch`, `delete`

**Likely false positives**

- Normal application deployments that carry their own policies.

**ATT&CK** attack.t1562.001

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_network_policy_changed.yaml>

### 🟠 high — Kubernetes NodePort Service Created

`631fa06f-c644-58b0-b69d-d2f6c060c2f2` · [`rules/k8s/k8s_nodeport_created.yml`](../rules/k8s/k8s_nodeport_created.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation of NodePort services which expose cluster ports externally - potential unauthorized network exposure. Ported from samma-io/siem-rules rule k8s-nodeport-created.

**Fires when** `kind` is `Event` and `objectRef.resource` is `services` and `verb` is `create` and `requestObject.spec.type` is `NodePort`

**Likely false positives**

- Services that are meant to be exposed on the node network.

**ATT&CK** attack.t1133

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_nodeport_created.yaml>

### 🟠 high — Kubernetes Pod Created In kube-system

`45e97ba6-efa0-5385-b50f-4f97251ec609` · [`rules/k8s/k8s_kube_system_pod.yml`](../rules/k8s/k8s_kube_system_pod.yml) · 3 tests (1 firing)

> **Status: experimental.**

Detects pod creation in kube-system namespace - may indicate masquerading as system components. Narrowed from the source rule to creates on the pods collection, so an exec or attach into a kube-system pod is not reported as a new pod. Ported from samma-io/siem-rules rule k8s-kube-system-pod.

**Fires when** `kind` is `Event` and `objectRef.resource` is `pods` and `verb` is `create` and `objectRef.namespace` is `kube-system` and `requestURI` matches the regular expression `/pods(\?|$)`

**Likely false positives**

- Cluster add-ons and DaemonSet rollouts in kube-system.

**ATT&CK** attack.t1036

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_kube_system_pod.yaml>

### 🟠 high — Kubernetes Port Forward To Pod

`d76549f4-6bd1-5232-9147-52c368fb03a0` · [`rules/k8s/k8s_port_forward.yml`](../rules/k8s/k8s_port_forward.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects port forwarding to pods - may indicate protocol tunneling or unauthorized access to internal services. Ported from samma-io/siem-rules rule k8s-port-forward.

**Fires when** `kind` is `Event` and `objectRef.resource` is `pods` and `objectRef.subresource` is `portforward` and `verb` is `create`

**Likely false positives**

- Developers reaching a service through kubectl port-forward.

**ATT&CK** attack.t1572

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_port_forward.yaml>

### 🟠 high — Kubernetes Role Or ClusterRole Modified

`3995db62-57da-57cd-8f11-f21ab43e3c16` · [`rules/k8s/k8s_rbac_modified.yml`](../rules/k8s/k8s_rbac_modified.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects modification of RBAC roles or cluster roles - may indicate privilege escalation or account manipulation. Ported from samma-io/siem-rules rule k8s-rbac-modified.

**Fires when** `kind` is `Event` and `verb` is one of `update`, `patch` and `objectRef.resource` is one of `clusterroles`, `roles`

**Likely false positives**

- Helm upgrades and operators reconciling their own roles.

**ATT&CK** attack.t1098

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_rbac_modified.yaml>

### 🟠 high — Kubernetes Secret Created, Changed Or Deleted

`24c61686-b618-5917-a184-c53dd1196fa6` · [`rules/k8s/k8s_secret_modified.yml`](../rules/k8s/k8s_secret_modified.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation, update, or deletion of secrets - may indicate credential tampering or exfiltration setup. Ported from samma-io/siem-rules rule k8s-secret-modified.

**Fires when** `kind` is `Event` and `objectRef.resource` is `secrets` and `verb` is one of `create`, `update`, `patch`, `delete`

**Likely false positives**

- Deployments, cert-manager renewals and secret operators.

**ATT&CK** attack.t1552.007

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_secret_modified.yaml>

### 🟠 high — Kubernetes Secret Read

`a44d32ae-e879-57ea-9cba-f513d69b3076` · [`rules/k8s/k8s_secret_accessed.yml`](../rules/k8s/k8s_secret_accessed.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects access to Kubernetes secrets (get/list) which may indicate credential harvesting. Ported from samma-io/siem-rules rule k8s-secret-accessed.

**Fires when** `kind` is `Event` and `objectRef.resource` is `secrets` and `verb` is one of `get`, `list`, `watch`

**Likely false positives**

- Controllers and workloads that read their own secrets.

**ATT&CK** attack.t1552.007

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_secret_accessed.yaml>

### 🟠 high — Kubernetes ServiceAccount Token Requested

`9d723255-9c22-5374-a9b4-97e995fbd4b4` · [`rules/k8s/k8s_token_created.yml`](../rules/k8s/k8s_token_created.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects service account token generation requests - may indicate credential theft or unauthorized access attempts. Ported from samma-io/siem-rules rule k8s-token-created.

**Fires when** `kind` is `Event` and `objectRef.resource` is `serviceaccounts` and `objectRef.subresource` is `token` and `verb` is `create`

**Likely false positives**

- The kubelet requesting projected tokens for pods.

**ATT&CK** attack.t1528, attack.t1078.004

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_token_created.yaml>

### 🟠 high — Kubernetes Workload Deleted

`991bc12c-060f-56a6-9cfb-9d9c79b3cc15` · [`rules/k8s/k8s_deployment_deleted.yml`](../rules/k8s/k8s_deployment_deleted.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects deletion of deployments, statefulsets, or daemonsets - potential data destruction or service disruption. Ported from samma-io/siem-rules rule k8s-deployment-deleted.

**Fires when** `kind` is `Event` and `verb` is `delete` and `objectRef.resource` is one of `deployments`, `statefulsets`, `daemonsets`

**Likely false positives**

- Uninstalling an application, or a GitOps controller pruning it.

**ATT&CK** attack.t1485

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_deployment_deleted.yaml>

### 🟡 medium — Kubernetes API Request Forbidden

`6663d741-20f1-52a5-bc1d-f98345dd327b` · [`rules/k8s/k8s_forbidden_access.yml`](../rules/k8s/k8s_forbidden_access.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects 403 Forbidden responses from the API server - indicates RBAC probing or unauthorized access attempts. Ported from samma-io/siem-rules rule k8s-forbidden-access.

**Fires when** `kind` is `Event` and `responseStatus.code` is `403`

**Likely false positives**

- Controllers starting before their RBAC is applied; users running a command they lack rights for.

**ATT&CK** attack.t1613

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_forbidden_access.yaml>

### 🟡 medium — Kubernetes CronJob Created

`fde69c96-1eb9-5b3a-8ceb-1fce61b8a842` · [`rules/k8s/k8s_cronjob_created.yml`](../rules/k8s/k8s_cronjob_created.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation of CronJob resources which can be used for persistence via scheduled execution. Ported from samma-io/siem-rules rule k8s-cronjob-created.

**Fires when** `kind` is `Event` and `objectRef.resource` is `cronjobs` and `verb` is `create`

**Likely false positives**

- Deployments that ship scheduled jobs (backups, reports).

**ATT&CK** attack.t1053.007

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_cronjob_created.yaml>

### 🟡 medium — Kubernetes Ingress Created

`b7804635-afef-5c26-9940-ca9c7ae99502` · [`rules/k8s/k8s_ingress_created.yml`](../rules/k8s/k8s_ingress_created.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects creation of Ingress resources which expose services externally. Ported from samma-io/siem-rules rule k8s-ingress-created.

**Fires when** `kind` is `Event` and `objectRef.resource` is `ingresses` and `verb` is `create`

**Likely false positives**

- Normal application deployments.

**ATT&CK** attack.t1133

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_ingress_created.yaml>

### 🟡 medium — Kubernetes ServiceAccount Created

`a93db80d-639a-57a7-90f4-0a7b797ea370` · [`rules/k8s/k8s_service_account_created.yml`](../rules/k8s/k8s_service_account_created.yml) · 3 tests (1 firing)

> **Status: experimental.**

Detects creation of new service accounts which could be used for persistence or privilege escalation. Narrowed from the source rule to creates on the serviceaccounts collection, so a token request (serviceaccounts/token) is reported only by k8s_token_created. Ported from samma-io/siem-rules rule k8s-service-account-created.

**Fires when** `kind` is `Event` and `objectRef.resource` is `serviceaccounts` and `verb` is `create` and `requestURI` matches the regular expression `/serviceaccounts(\?|$)`

**Likely false positives**

- Normal application deployments.

**ATT&CK** attack.t1136

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_service_account_created.yaml>

### 🟡 medium — Kubernetes Workload Patched

`afdd1a35-8577-5c03-ab7e-aa9b671de93a` · [`rules/k8s/k8s_workload_patched.yml`](../rules/k8s/k8s_workload_patched.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects patch operations on deployments, daemonsets, or statefulsets - may indicate sidecar injection or unauthorized modification. Ported from samma-io/siem-rules rule k8s-workload-patched.

**Fires when** `kind` is `Event` and `verb` is `patch` and `objectRef.resource` is one of `deployments`, `daemonsets`, `statefulsets`

**Likely false positives**

- kubectl rollout restart, scaling, and GitOps reconciliation.

**ATT&CK** attack.t1610

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_workload_patched.yaml>

### 🔵 low — Kubernetes Identity Check (kubectl auth whoami)

`0cc55620-7b42-5d35-bda1-8849ba1c9be9` · [`rules/k8s/k8s_user_login.yml`](../rules/k8s/k8s_user_login.yml) · 5 tests (2 firing)

> **Status: experimental.**

Detects a SelfSubjectReview, the request behind kubectl auth whoami, which asks the API server which identity a credential authenticates as. Someone holding a token they did not mint (a leaked kubeconfig, a stolen service account token) typically runs this first. Kubernetes has no login event: every request authenticates on its own and is audited as itself. The rule this was ported from, samma-io/siem-rules k8s-user-login, keyed on verb authenticate on users, which the API server never writes. TokenReviews are not a substitute: they are made by components (metrics-server, aggregated API servers, webhook authenticators) checking someone else's token, so user names the reviewer, not the person, and they arrive constantly.

**Fires when** `kind` is `Event` and `verb` is `create` and `objectRef.apiGroup` is `authentication.k8s.io` and `objectRef.resource` is `selfsubjectreviews`

**Likely false positives**

- Administrators running kubectl auth whoami to check which context they are in.

**ATT&CK** attack.t1033, attack.t1078

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_user_login.yaml>
- <https://kubernetes.io/docs/reference/access-authn-authz/authentication/#self-subject-review>

### 🔵 low — Kubernetes Pod Created

`7a014823-d705-52f6-9a1d-d490348e53cb` · [`rules/k8s/k8s_pod_created.yml`](../rules/k8s/k8s_pod_created.yml) · 5 tests (1 firing)

> **Status: experimental.**

Detects new pod creation in the cluster via API server audit logs. Narrowed from the source rule: subresource requests (exec, attach, port-forward, binding) and the pods covered at higher severity by k8s_kube_system_pod and k8s_privileged_pod are excluded, so one request raises one alert. Ported from samma-io/siem-rules rule k8s-pod-created.

**Fires when** (`kind` is `Event` and `objectRef.resource` is `pods` and `verb` is `create` and `requestURI` matches the regular expression `/pods(\?|$)`) **and not** ((`requestObject.spec.hostNetwork` is `true` or `requestObject.spec.hostPID` is `true` or `requestObject.spec.hostIPC` is `true`) **or** `objectRef.namespace` is `kube-system`)

**Likely false positives**

- Every rollout, scale-up and job run. Informational on its own.

**ATT&CK** attack.t1610

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_pod_created.yaml>

### 🔵 low — Kubernetes Pod Logs Read

`ef2e5e80-da23-5adf-8b45-1b7176242284` · [`rules/k8s/k8s_pod_log_access.yml`](../rules/k8s/k8s_pod_log_access.yml) · 2 tests (1 firing)

> **Status: experimental.**

Detects access to pod logs via API - may indicate reconnaissance to extract sensitive data from application output. Ported from samma-io/siem-rules rule k8s-pod-log-access.

**Fires when** `kind` is `Event` and `objectRef.resource` is `pods` and `objectRef.subresource` is `log` and `verb` is `get`

**Likely false positives**

- Log shippers and operators reading logs while debugging.

**ATT&CK** attack.t1613

- <https://github.com/samma-io/siem-rules/blob/main/rules/k8s/k8s_pod_log_access.yaml>

---

## onepassword

### 🟠 high — 1Password Item Revealed From An Unmanaged Client

`3f1c9a20-5d7b-4e11-8c33-9a1b2c3d4e5f` · [`rules/onepassword/item_revealed_by_unmanaged_client.yml`](../rules/onepassword/item_revealed_by_unmanaged_client.yml) · 3 tests (1 firing)

> **Status: experimental.**

A vault item was revealed or exported through a client that is not a managed 1Password application. Reveal is the action that actually exposes a secret, and an unmanaged client is how one leaves the fleet.

**Fires when** (`source` is `onepassword` and `feed` is `itemusages` and `action` is one of `reveal`, `export`) **and not** `client.app_name` starts with `1Password`

**Likely false positives**

- A newly released 1Password client whose app_name changed.

**ATT&CK** attack.credential_access

- <https://developer.1password.com/docs/events-api/>

### 🟠 high — 1Password Vault Or Group Deleted

`9e4b7c02-1a68-4f53-bc90-6d7e8f9a0b1c` · [`rules/onepassword/vault_or_group_deleted.yml`](../rules/onepassword/vault_or_group_deleted.yml) · 3 tests (1 firing)

> **Status: experimental.**

A vault or a group was deleted. Vault deletion destroys shared credentials for everyone who had access, and group deletion silently removes that access -- so both read as destruction of a control, whether or not they were intended.

**Fires when** `source` is `onepassword` and `feed` is `auditevents` and `action` is `delete` and `object_type` is one of `vault`, `group`

**Likely false positives**

- Planned cleanup of a decommissioned vault.

**ATT&CK** attack.impact

- <https://developer.1password.com/docs/events-api/>

### 🟡 medium — 1Password Sign-In Failure

`7a2d4b61-8e39-4c02-b5d7-1f2e3a4b5c6d` · [`rules/onepassword/signin_failure.yml`](../rules/onepassword/signin_failure.yml) · 3 tests (2 firing)

> **Status: experimental.**

A failed sign-in on the 1Password Events API. Credential failures against the password manager itself are the precursor to everything else in the vault. Deliberately medium: a single mistyped password is not an incident, and this earns its keep by volume and by correlation rather than alone.

**Fires when** `source` is `onepassword` and `feed` is `signinattempts` and `category` is one of `credentials_failed`, `mfa_failed`

**Likely false positives**

- A user mistyping a password, which is why this is not high.

**ATT&CK** attack.credential_access

- <https://developer.1password.com/docs/events-api/>

---

## scanner

### 🟠 high — Administrative Or Database Port Reachable On A Scanned Target

`053a9feb-5096-46f4-9a5b-0bdf6d0596f7` · [`rules/scanner/scanner_admin_port_exposed.yml`](../rules/scanner/scanner_admin_port_exposed.yml) · 4 tests (1 firing)

> **Status: experimental.**

The detect port-scanner found a management, database or cluster-internal port (SSH, RDP, PostgreSQL, Redis, the kubelet, ...) accepting connections on a target the organisation scans. This is the schema v2 successor of samma-io/siem-rules nmap-open-port: an ordinary open port is an INFO inventory fact (SAMMA-PORT-OPEN) and does not alert; an exposed admin service is a finding. endpoint carries the host, port and service name.

**Fires when** `schema` is `samma.io/scan/v2` and `kind` is `finding` and `checkId` is `SAMMA-PORT-OPEN-ADMIN`

**Likely false positives**

- A bastion or service that is meant to be public on an admin port, such as SSH on a jump host.

**ATT&CK** attack.discovery, attack.t1046

- <https://github.com/samma-io/siem-rules/blob/main/rules/nmap/nmap-portscan.yaml>
- <https://github.com/samma-io/detect/blob/main/common/samma_finding/catalog/port_scanner.py>

### 🟠 high — High Or Critical Severity Scanner Finding

`3cd1f737-b3f3-40a0-af2a-e460eafe2594` · [`rules/scanner/scanner_high_severity_finding.yml`](../rules/scanner/scanner_high_severity_finding.yml) · 8 tests (3 firing)

> **Status: experimental.**

A Samma detect scanner reported a HIGH or CRITICAL finding on a scanned target: today a deprecated TLS protocol, an expired or invalid certificate, SSH protocol 1, or an expired domain registration. The checkId names the check and endpoint the host and port. Checks with a rule of their own (SAMMA-PORT-OPEN-ADMIN) are excluded so one finding raises one alert. A run message, or a finding at MEDIUM and below, never fires.

**Fires when** (`schema` is `samma.io/scan/v2` and `kind` is `finding` and `severity` is one of `HIGH`, `CRITICAL`) **and not** `checkId` is `SAMMA-PORT-OPEN-ADMIN`

**Likely false positives**

- A test or staging host that is knowingly left on an old configuration.

- <https://github.com/samma-io/detect#the-check-catalogue>

### 🟠 high — Nikto Finding With An OSVDB Reference

`986854c1-e287-4db1-bf23-82d4fa901a9a` · [`rules/scanner/scanner_nikto_osvdb_finding.yml`](../rules/scanner/scanner_nikto_osvdb_finding.yml) · 4 tests (1 firing)

> **Status: experimental.**

The classic nikto scanner (samma-io/nikto, run by the operator as nikto) reported a finding that Nikto ties to a known OSVDB entry. nikto still emits legacy v1 records through sammaParser, one per row of Nikto's CSV report: host, ip, port, OSVDB, request, nikto_url, finding. The image installs Ubuntu's Nikto 2.1.5, whose CSV writes OSVDB-<n> with n=0 for a finding without an entry and leaves the column empty on the per-host banner row; both are excluded. Ported from samma-io/siem-rules rule nikto-critical-finding.

**Fires when** `type` is `Nikto` and `OSVDB` matches the regular expression `^OSVDB-[1-9]`

**Likely false positives**

- Informational OSVDB entries (directory indexing, default files) on hosts where they are expected.

**ATT&CK** attack.initial_access, attack.t1190

- <https://github.com/samma-io/siem-rules/blob/main/rules/nikto/nikto-findings.yaml>
- <https://github.com/samma-io/nikto/blob/main/code/scan.py>

### 🟡 medium — Open TCP Port Reported By The nmap Scanner

`8667c34a-e4b6-4fb4-95da-c959b9432be3` · [`rules/scanner/scanner_nmap_open_tcp_port.yml`](../rules/scanner/scanner_nmap_open_tcp_port.yml) · 6 tests (1 firing)

> **Status: experimental.**

The classic nmap port scanner (samma-io/nmap nmap_portscanner.py, run by the operator as nmap/port) listed a TCP port on a scanned target. nmap still emits legacy v1 records through sammaParser -- type, scanner, target, port and protocol at the top level plus the samma-io block -- and no schema field. The record does not carry the port state, so this fires on every port nmap lists, which is the open ones in the common case. Ported from samma-io/siem-rules rule nmap-open-port.

**Fires when** `type` is `nmap` and `scanner` is `nmap_port` and `protocol` is `tcp`

**Likely false positives**

- Every service the target is meant to expose (80, 443). Tune per target.

**ATT&CK** attack.discovery, attack.t1046

- <https://github.com/samma-io/siem-rules/blob/main/rules/nmap/nmap-portscan.yaml>
- <https://github.com/samma-io/nmap/blob/main/nmap_portscanner.py>

---

## slack

### 🟡 medium — Slack App Added To The Workspace

`5c8e1f34-2b70-4a95-8d16-3e4f5a6b7c8d` · [`rules/slack/app_added_to_workspace.yml`](../rules/slack/app_added_to_workspace.yml) · 3 tests (1 firing)

> **Status: experimental.**

A third-party app was added to the workspace. App install is the shortest path to bulk Slack data access and it needs no password, so every install is worth a look even though most are routine. Deliberately not scoped to dangerous permissions. team.integrationLogs does not return a scope field in practice -- 0 of the live records carry one, though Slack's API documentation lists it -- so a rule that filtered on scope would load, report healthy and never fire. Triage on app_type and user_name instead, which are always present.

**Fires when** `source` is `slack` and `feed` is `integrationlogs` and `change_type` is `added`

**Likely false positives**

- Any approved integration being installed, which is most of them. This is a visibility rule; the judgement is in the triage, not the match.

**ATT&CK** attack.persistence, attack.collection

- <https://api.slack.com/scopes>
- <https://api.slack.com/methods/team.integrationLogs>

### 🟡 medium — Slack Sign-In From A Hosting Or Anonymising Network

`2f8c4b17-6d93-4e51-a072-5b8c9d0e1f23` · [`rules/slack/signin_from_hosting_provider.yml`](../rules/slack/signin_from_hosting_provider.yml) · 5 tests (2 firing)

> **Status: experimental.**

A Slack sign-in came from an address belonging to a hosting provider or commercial VPN rather than a consumer or corporate network. Staff sign in from ISPs; an address in a data centre means either a proxy chosen to obscure origin, or a session being driven from infrastructure rather than a laptop. This workspace is on Business+, which has no audit log at all -- team.accessLogs is the only sign-in visibility that exists here, so it is worth using well. Cloudflare Warp is excluded deliberately: it is the corporate VPN and is the single largest source of sign-ins on this lane. Alerting on it would bury the rule within a day.

**Fires when** (`source` is `slack` and `feed` is `accesslogs`) **and** `isp` is one of `Datacamp`, `OVHcloud`, `Servers Tech Fzco`, `Amazon.com`, `Cloudflare` **and not** `isp` is `Cloudflare Warp`

**Likely false positives**

- An engineer working through a personal VPN. Worth asking about rather than assuming; the answer is usually quick.
- A Slack app or integration calling from cloud infrastructure. Those appear with an ApiApp user agent and are worth distinguishing before tuning.

**ATT&CK** attack.initial_access, attack.t1078.004

- <https://api.slack.com/methods/team.accessLogs>

---

## workspace

### 🔴 critical — Google Workspace Admin Role Granted

`8d3f5c72-9a41-4b63-a7e8-2c3d4e5f6a7b` · [`rules/workspace/admin_role_granted.yml`](../rules/workspace/admin_role_granted.yml) · 5 tests (2 firing)

> **Status: experimental.**

A user was assigned an administrator role or granted an admin privilege. Privilege grant in the identity provider is the highest-leverage change anyone can make in the estate, because everything else federates from it.

**Fires when** `source` is `workspace` and `feed` is `admin` and `name` is one of `ASSIGN_ROLE`, `GRANT_ADMIN_PRIVILEGE`, `GRANT_DELEGATED_ADMIN_PRIVILEGES`

**Likely false positives**

- A planned administrator onboarding.

**ATT&CK** attack.privilege_escalation

- <https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin>

### 🔴 critical — Google Workspace Two-Step Verification Disabled

`4b7e2a95-3c18-4d76-9e02-7a8b9c0d1e2f` · [`rules/workspace/two_step_verification_disabled.yml`](../rules/workspace/two_step_verification_disabled.yml) · 2 tests (1 firing)

> **Status: experimental.**

Enforcement of two-step verification was turned off, for the org or for a user. This is the control that makes a stolen Workspace password survivable, and turning it off is a standard step before account takeover.

**Fires when** `source` is `workspace` and `feed` is `admin` and `name` is one of `UNENFORCE_STRONG_AUTHENTICATION`, `ALLOW_STRONG_AUTHENTICATION`, `TURN_OFF_2_STEP_VERIFICATION`

**Likely false positives**

- A documented break-glass change during an MFA migration.

**ATT&CK** attack.defense_evasion, attack.persistence

- <https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin>

