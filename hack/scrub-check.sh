#!/usr/bin/env sh
# Generic gate: fail if anything that looks like a private-organisation identifier
# is present in the tree. Public repos may only contain documentation/example values.
# Usage: hack/scrub-check.sh [path]   (exit 0 = clean)
set -eu
ROOT="${1:-.}"
# Documentation / example values that are allowed to appear.
ALLOW_ACCOUNTS='123456789012|111111111111|222222222222|333333333333|999999999999|000000000000'
# Placeholder Slack channel id used in examples.
ALLOW_SLACK='C0EXAMPLE1'
fail=0
report() { echo "scrub-check: $1"; fail=1; }
hits() { grep -rInE --exclude-dir=.git --exclude-dir=.terraform --exclude=scrub-check.sh "$@" "$ROOT" || true; }

# 12-digit AWS account ids not in the allowlist
out=$(hits '\b[0-9]{12}\b' | grep -vE "$ALLOW_ACCOUNTS" || true)
[ -n "$out" ] && report "AWS account id(s):" && echo "$out"
# AWS organisation ids, real-looking VPC ids, Slack channel ids
out=$(hits '\bo-[a-z0-9]{10}\b|\bvpc-0[0-9a-f]{16}\b|\bC0[A-Z0-9]{8}\b' | grep -vE "$ALLOW_SLACK" || true)
[ -n "$out" ] && report "org/vpc/slack id(s):" && echo "$out"
# Previous owner's names and tooling
out=$(hits -i 'hellohippo|labhack|hippo\.tools|hippo-tf|hsdk|secteam|panther|integsrv|rightstart|right_start|secureframe|cloud\.wazuh\.com')
[ -n "$out" ] && report "private organisation name(s):" && echo "$out"
# Internal ticket ids
out=$(hits -E '\bhippo-[a-z0-9]{3,4}\b')
[ -n "$out" ] && report "internal ticket id(s):" && echo "$out"
# Email addresses other than example domains
out=$(hits -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' | grep -vE '@(example\.(com|org|net)|users\.noreply\.github\.com|apache\.org|samma\.io)' || true)
[ -n "$out" ] && report "email address(es):" && echo "$out"

[ "$fail" -eq 0 ] && echo "scrub-check: clean" || exit 1
