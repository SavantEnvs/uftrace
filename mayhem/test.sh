#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# uftrace's unit tests (tests/unittest, built by build.sh with the normal flags) assert on the
# project's own parsers; its stats block is parsed below. The exit code of that runner is not
# trusted on its own: a runner that prints nothing counts as a failure.
unittest="$SRC/tests/unittest"
demangler="$SRC/.build/test/misc/demangler"
for f in "$unittest" "$demangler"; do
  [ -x "$f" ] || { echo "missing $f: mayhem/build.sh should have built it" >&2; emit_ctrf "uftrace" 0 1 0; exit 1; }
done

passed=0 failed=0 skipped=0

out=$(cd "$SRC/tests" && "$unittest" 2>&1) || true
printf '%s\n' "$out" | tail -n 12
ran=$(printf '%s\n' "$out" | sed -n 's/^ *\([0-9][0-9]*\) ran successfully.*/\1/p' | tail -n 1)
bad=$(printf '%s\n' "$out" | sed -n 's/^ *\([0-9][0-9]*\) failed.*/\1/p' | tail -n 1)
skip=$(printf '%s\n' "$out" | sed -n 's/^ *\([0-9][0-9]*\) skipped.*/\1/p' | tail -n 1)
sig=$(printf '%s\n' "$out" | sed -n 's/^ *\([0-9][0-9]*\) signal caught.*/\1/p' | tail -n 1)
unk=$(printf '%s\n' "$out" | sed -n 's/^ *\([0-9][0-9]*\) unknown result.*/\1/p' | tail -n 1)
if [ -z "$ran" ] || [ "$ran" -lt 100 ]; then
  echo "FAIL unittest: expected >= 100 passing tests, got '${ran:-none}'" >&2
  failed=$((failed + 1))
else
  passed=$((passed + ran))
fi
failed=$((failed + ${bad:-0} + ${sig:-0} + ${unk:-0}))
skipped=$((skipped + ${skip:-0}))

# Known-answer probes through the dynamically linked demangler tool (exit code alone proves nothing).
kat() {
  local mangled="$1" want="$2" got
  got=$("$demangler" "$mangled" 2>/dev/null)
  if [ "$got" = "$want" ]; then
    passed=$((passed + 1))
  else
    echo "FAIL demangle $mangled: want '$want', got '$got'" >&2
    failed=$((failed + 1))
  fi
}
kat _ZN3ABC3fooEv "ABC::foo"
kat _ZN3ABCC1Ei "ABC::ABC"
kat _Znwm "operator new"
kat _ZN2ns3bar3bazEi "ns::bar::baz"
kat _ZN2ns3barEi "ns::bar"
kat _ZThn8_N13FtraceServiceD0Ev "FtraceService::~FtraceService"
kat _ZN4node8Watchdog7DestroyEv.part.0 "node::Watchdog::Destroy"
kat main "main"

emit_ctrf "uftrace" "$passed" "$failed" "$skipped"
