#!/usr/bin/env sh
# Build rules-<version>.tar.gz: the shippable rules tree.
#
# The tarball is what aws-siem uploads to the rules bucket. It contains the
# lane directories (<lane>/sigma-config.yml and <lane>/*.yml) and nothing
# else: sidecars are excluded because the engine would try to load a
# .tests.yml as a rule and refuse to start, and rules/examples/ is excluded
# because those rules carry placeholder values.
#
# Usage: hack/package-rules.sh <version> [outdir]
set -eu
VERSION="${1:?usage: package-rules.sh <version> [outdir]}"
OUT="${2:-.}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="rules-${VERSION}.tar.gz"
# Resolve the output directory before changing into rules/.
case "$OUT" in /*) ;; *) OUT="$(pwd)/$OUT" ;; esac
mkdir -p "$OUT"

cd "$ROOT/rules"
# Stable file order so the archive is reproducible for one tree.
FILES=$(find . -type f \( -name '*.yml' -o -name '*.yaml' \) \
          ! -name '*.tests.yml' ! -path './examples/*' | sort)
[ -n "$FILES" ] || { echo "package-rules: no rule files found under $ROOT/rules" >&2; exit 1; }


# GNU tar can normalise ownership and mtime; bsdtar (macOS) cannot, so the
# archive is byte-reproducible in CI and merely correct elsewhere.
if tar --version 2>/dev/null | grep -q GNU; then
  MTIME=${SOURCE_DATE_EPOCH:+--mtime=@$SOURCE_DATE_EPOCH}
  # shellcheck disable=SC2086
  echo "$FILES" | tar --owner=0 --group=0 --numeric-owner $MTIME -czf "$OUT/$NAME" -T -
else
  echo "$FILES" | tar -czf "$OUT/$NAME" -T -
fi

cd "$OUT"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$NAME" > "$NAME.sha256"
else
  shasum -a 256 "$NAME" > "$NAME.sha256"
fi
echo "wrote $OUT/$NAME ($(echo "$FILES" | wc -l | tr -d ' ') files)"
cat "$NAME.sha256"
