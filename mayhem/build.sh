#!/usr/bin/env bash
#
# mayhem/build.sh — build uftrace's fuzz harnesses and its unit-test suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# uftrace builds out of tree (`.build/<name>`, gitignored upstream) with its own ./configure + make.
# Both trees are rebuilt from scratch so a re-run (also offline, also after `git clean -ffdX`) is identical.
test_dir="$SRC/.build/test"
fuzz_dir="$SRC/.build/fuzz"
rm -rf "$test_dir" "$fuzz_dir"

# Only the base image's packages are available (no libelf/libdw/...), so uftrace uses its own ELF parser.
configure_opts=(--without-libelf)

# 1) The sanitized project. configure bakes CFLAGS into .config as an `override`, so they go to
#    configure, not make. -fsanitize=fuzzer-no-link puts SanCov in the library code, not just the
#    harness; $DEBUG_FLAGS goes last so -gdwarf-3 wins (DWARF <= 3).
#    -fno-sanitize=nonnull-attribute is the one relaxed UBSan check: a symbol file or ELF without
#    symbols reaches qsort(NULL, 0, ...) in load_module_symbol_file(), a harmless call that would
#    otherwise halt every such input.
mkdir -p "$fuzz_dir"
(
  cd "$fuzz_dir"
  CC="$CC" CFLAGS="$SANITIZER_FLAGS -fno-sanitize=nonnull-attribute -fsanitize=fuzzer-no-link $DEBUG_FLAGS" LDFLAGS="" \
    "$SRC/configure" "${configure_opts[@]}" >/dev/null
  make prepare >/dev/null
)
make -C "$SRC" -j"$MAYHEM_JOBS" objdir="$fuzz_dir" "$fuzz_dir/uftrace"

# uftrace.o holds main() and parse_script_opt(); keep the latter, rename the former.
objcopy --redefine-sym main=uftrace_main "$fuzz_dir/uftrace.o" "$fuzz_dir/uftrace_lib.o"

# The project's own compile definitions (-D_GNU_SOURCE, -DHAVE_*), so the harnesses see the same
# struct layouts as the objects they link.
defs=$(make -C "$SRC" -n -W "$SRC/utils/demangle.c" V=1 objdir="$fuzz_dir" "$fuzz_dir/utils/demangle.o" \
         | grep -o -e ' -D[A-Za-z_0-9=]*' | sort -u | tr '\n' ' ')
arch_lib=$(ls "$fuzz_dir"/arch/*/uftrace-arch.a)

# 2) Harnesses: a libFuzzer binary and a `-standalone` run-once reproducer for each.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$fuzz_dir/lsan_off.o"

# libstdc++ (via $CXX) is needed by the sanitizer runtime and by uftrace's __cxa_demangle use.
# The run-once driver is C: compile it as C so its LLVMFuzzerTestOneInput reference isn't mangled.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$fuzz_dir/standalone_main.o"

targets="fuzz_demangle fuzz_elf fuzz_filter fuzz_info fuzz_symfile"
for t in $targets; do
  $CC -std=gnu11 $defs $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS \
      -iquote "$SRC" -iquote "$fuzz_dir" -iquote "$SRC/arch/$(basename "$(dirname "$arch_lib")")" \
      -Wno-unused-value -c "$SRC/mayhem/$t.c" -o "$fuzz_dir/$t.o"

  objs=("$fuzz_dir/$t.o" "$fuzz_dir/lsan_off.o" "$fuzz_dir/uftrace_lib.o"
        "$fuzz_dir"/utils/*.o "$fuzz_dir"/cmds/*.o "$arch_lib")
  syslibs=(-ldl -pthread -lrt -lm)

  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" "${syslibs[@]}" -o "$SRC/$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$fuzz_dir/standalone_main.o" "${objs[@]}" "${syslibs[@]}" \
      -o "$SRC/$t-standalone"
done

# 3) The test suite and the small CLI tools test.sh probes, with the project's NORMAL flags (no
#    sanitizers, no -gdwarf-3, none of the fuzzer's instrumentation).
mkdir -p "$test_dir"
(
  cd "$test_dir"
  env -u CFLAGS -u LDFLAGS CC="$CC" CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    "$SRC/configure" "${configure_opts[@]}" >/dev/null
  make prepare >/dev/null
)
env -u CFLAGS -u LDFLAGS make -C "$SRC" -j"$MAYHEM_JOBS" objdir="$test_dir" \
    unittest "$test_dir/misc/demangler" "$test_dir/misc/symbols"
