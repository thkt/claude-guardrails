#!/usr/bin/env bash
# Precision delta gate (ADR-0019): fails when either axis of the
# precision harness snapshot worsens on head vs base:
#   - per-rule FP rate (rules.<id>.fp / .tn), compared via integer
#     cross-multiplication so corpus growth does not skew the ratio;
#   - the override-application axis (overrides.leak / .overreach), which
#     must not increase (see src/hook/precision.rs OverrideMetrics doc).
# `jq` must error (not read null) on any schema drift, and this script must
# observe that error: a bare `report=$(jq ...)` masks jq's exit status under
# `set -e`, so a renamed/missing field would exit 0 and the gate would
# silently disable (ADR-0019 schema contract). `// error(...)` makes a
# missing field fatal; `if ! report=$(...)` propagates it.
#
# Usage:
#   precision_gate.sh <base.json> <head.json>   # real gate run (ci.yml)
#   precision_gate.sh --self-check               # fixture self-check (below)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/precision_gate"

JQ_FILTER='
def rule_report:
  ($base[0].rules // {}) as $b
  | ($head[0].rules // error("head metrics: .rules key missing (schema drift? see ADR-0019)"))
  | to_entries[]
  | .key as $rule | .value as $h | $b[$rule] as $br
  | if $br == null then
      "SKIP \($rule): absent from base metrics (new rule)"
    else
      ($h.fp // error("head rule \($rule): fp field missing")) as $hfp
      | ($h.tn // error("head rule \($rule): tn field missing")) as $htn
      | ($br.fp // error("base rule \($rule): fp field missing")) as $bfp
      | ($br.tn // error("base rule \($rule): tn field missing")) as $btn
      | if ($hfp * ($bfp + $btn)) > ($bfp * ($hfp + $htn)) then
          "FAIL \($rule): FP rate worsened, base \($bfp)/\($bfp + $btn) -> head \($hfp)/\($hfp + $htn)"
        else empty end
    end;

# base predating the override axis (U-002) is a bootstrap, not a failure:
# the axis has nothing to compare against yet.
def override_report:
  if ($base[0].overrides // null) == null then
    "SKIP overrides: absent from base metrics (bootstrap, base predates the override axis)"
  else
    ($base[0].overrides) as $bo
    | ($head[0].overrides // error("head metrics: .overrides key missing (schema drift? see ADR-0019)")) as $ho
    | ($bo.leak // error("base overrides: leak field missing")) as $bleak
    | ($bo.overreach // error("base overrides: overreach field missing")) as $boverreach
    | ($ho.leak // error("head overrides: leak field missing")) as $hleak
    | ($ho.overreach // error("head overrides: overreach field missing")) as $hoverreach
    | (if $hleak > $bleak then
        "FAIL overrides.leak: applied-override leak increased, base \($bleak) -> head \($hleak)"
      else empty end),
      (if $hoverreach > $boverreach then
        "FAIL overrides.overreach: applied-override overreach increased, base \($boverreach) -> head \($hoverreach)"
      else empty end)
  end;

rule_report, override_report
'

# run_gate <base.json> <head.json>
# Prints the report (SKIP/FAIL lines, empty when clean) and returns 0 on
# pass/bootstrap or 1 on FAIL/schema-error.
run_gate() {
  local base_file="$1" head_file="$2" report
  if ! report=$(jq -rn --slurpfile base "$base_file" --slurpfile head "$head_file" "$JQ_FILTER"); then
    echo "::error::precision gate jq evaluation failed (metrics JSON schema drift? base/head field mismatch — see ADR-0019 schema contract)"
    return 1
  fi
  if [ -n "$report" ]; then printf '%s\n' "$report"; fi
  if printf '%s\n' "$report" | grep -q '^FAIL'; then
    echo "::error::precision gate failed (see FAIL lines above)"
    return 1
  fi
  echo "OK: no per-rule FP rate or override-axis regression"
  return 0
}

# self_check exercises both branches the corpus/schema-error path do not
# reliably reach on a given PR (a FAIL line, and the override-axis bootstrap
# skip) against fixed fixtures, so a jq/schema drift that silently disables
# the gate is caught even when the real base/head diff is clean.
self_check() {
  local status=0

  echo "precision_gate self-check: override-axis regression must FAIL the gate"
  if run_gate "$FIXTURE_DIR/fail/base.json" "$FIXTURE_DIR/fail/head.json" >/dev/null; then
    echo "::error::self-check: fail/ fixtures did not fail the gate (FAIL branch not exercised — gate logic drifted?)"
    status=1
  fi

  echo "precision_gate self-check: base missing the override axis must bootstrap-skip, not fail"
  if ! run_gate "$FIXTURE_DIR/bootstrap/base.json" "$FIXTURE_DIR/bootstrap/head.json" >/dev/null; then
    echo "::error::self-check: bootstrap/ fixtures unexpectedly failed the gate (skip branch not exercised — gate logic drifted?)"
    status=1
  fi

  if [ "$status" -ne 0 ]; then
    return 1
  fi
  echo "OK: precision_gate self-check passed (FAIL and bootstrap-skip branches both exercised)"
}

if [ "${1:-}" = "--self-check" ]; then
  self_check
  exit $?
fi

if [ $# -ne 2 ]; then
  echo "usage: precision_gate.sh <base.json> <head.json> | precision_gate.sh --self-check" >&2
  exit 2
fi

run_gate "$1" "$2"
