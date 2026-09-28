# Org-specific example rules

The rules in this directory only make sense once they carry facts about **your**
estate -- account ids, an email domain, 1Password vault uuids. They ship with
placeholder values, are never baked into the image, are skipped by the
`rulecheck` gate, and are never loaded by the engine.

| Rule | Lane | Fill in |
|---|---|---|
| `aws/root_activity_in_management_account.yml` | aws | `recipientAccountId` list: your Organizations management account id(s) |
| `aws/kms_s3_decrypt_by_a_person.yml` | aws | `userIdentity.arn\|contains`: your SSO email domain (replaces `@example.com`) |
| `onepassword/aws_root_vault_accessed.yml` | onepassword | `vault_uuid`: `REPLACE_WITH_AWS_ROOT_VAULT_UUID` |
| `onepassword/production_vault_accessed.yml` | onepassword | `vault_uuid`: `REPLACE_WITH_PRODUCTION_VAULT_UUID` |

## Enabling one

1. Copy the rule **and its `.tests.yml` sidecar** into the lane directory:

   ```bash
   cp rules/examples/org-specific/aws/root_activity_in_management_account{,.tests}.yml rules/aws/
   ```

2. Replace every placeholder in both files. The sidecar's positive cases must
   use the same values as the rule, and its negative cases must use different
   ones -- that is what proves the scoping works.

3. Run the gate and regenerate the catalogue:

   ```bash
   make test   # includes TestRules_* in internal/rulecheck
   make docs   # docs/RULES.md
   ```

   `TestRules_EveryRuleHasAPositiveTestCase` fails if a placeholder is left in
   only one of the two files, because the rule then cannot match its own test.

4. Ship the rules as usual: build and push a new image (`make image push`) and
   roll the lane's service, or, if you load rules from the bucket, re-apply
   aws-siem with your `rules_dir` and restart the lane's tasks.

Notes:

- `root_activity_in_management_account` deliberately overlaps
  `root_account_activity` and `console_login_without_mfa`. The pairs are
  already listed in `internal/rulecheck/overlap_test.go`, so enabling it does
  not trip `TestRules_DoNotSemanticallyDuplicateEachOther`.
- Vault uuids are opaque handles, not secrets, but they identify your tenant.
  Keep filled-in copies in a private fork or overlay, not in a public repo.
