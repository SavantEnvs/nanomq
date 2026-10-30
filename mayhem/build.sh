#!/usr/bin/env bash
#
# mayhem/build.sh — build NanoMQ's fuzz harnesses (sanitized, DWARF 3) and its unit tests (normal flags).
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem; offline-safe and re-runnable
# (all dependencies are the git submodules already in the tree; cmake fetches nothing).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# A re-run over a configured tree flips NANOMQ_TESTS back to OFF in the cmake cache, so start clean.
rm -rf build/fuzz build/tests

# Configuration shared by both builds: the broker library with the rule engine and ACL, no CLI/TLS/JWT.
COMMON_CMAKE=(
  -G Ninja
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  -DBUILD_STATIC_LIB=ON -DENABLE_RULE_ENGINE=ON -DENABLE_ACL=ON -DENABLE_JWT=OFF
  -DBUILD_NFTP=OFF -DBUILD_NANOMQ_CLI=OFF -DBUILD_CLIENT=OFF -DNNG_TESTS=OFF
)

# 1) Sanitized library for the fuzz targets. -fsanitize=fuzzer-no-link gives the library SanCov
#    instrumentation (the harness TU alone would record ~0 edges in the project code).
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1"
cmake -S . -B build/fuzz "${COMMON_CMAKE[@]}" -DNANOMQ_TESTS=OFF \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS"
ninja -C build/fuzz -j"$MAYHEM_JOBS" nanomq nng

# Harness compile flags = the library's own definitions, so struct layouts and NNG_DECL match.
DEFS=$( (cd build/fuzz && ninja -t commands nanomq nng) | grep -E 'rest_api\.c|mqtt_codec\.c' \
        | grep -oE ' -D[A-Za-z0-9_]+(=[A-Za-z0-9_.]+)?' | sort -u | tr '\n' ' ')
INCS="-Inanomq -Inanomq/include -Inng/include -Inng/src -Inng/src/core -Inng/src/supplemental"
LIBS="build/fuzz/nanomq/libnanomq.a build/fuzz/nng/libnng.a -lm -lpthread"

# Leak detection off at build time (SPEC §6.2 item 15).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
$CC  $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o

# In-tree harness sources (fuzz/) except fuzz_base64, fuzz_mqtt_codec and fuzz_nng_url, which mayhem/harnesses replaces (see their headers).
declare -A SOURCE=(
  [fuzz_acl_parser]=fuzz/fuzz_acl_parser.c
  [fuzz_base64]=mayhem/harnesses/fuzz_base64.c
  [fuzz_mqtt_codec]=mayhem/harnesses/fuzz_mqtt_codec.c
  [fuzz_mqtt_common_decoder]=fuzz/fuzz_mqtt_common_decoder.c
  [fuzz_mqtt_db]=fuzz/fuzz_mqtt_db.c
  [fuzz_nng_http]=fuzz/fuzz_nng_http.c
  [fuzz_nng_url]=mayhem/harnesses/fuzz_nng_url.c
  [fuzz_pub_handler]=fuzz/fuzz_pub_handler.c
  [fuzz_rest_api]=fuzz/fuzz_rest_api.c
  [fuzz_rule_sql]=fuzz/fuzz_rule_sql.c
  [fuzz_sub_handler]=fuzz/fuzz_sub_handler.c
  [fuzz_topic_repub]=fuzz/fuzz_topic_repub.c
  [fuzz_unsub_handler]=fuzz/fuzz_unsub_handler.c
  [pub_decode_fuzzer]=fuzz/pub_decode_fuzzer.c
)
for t in "${!SOURCE[@]}"; do
  src=${SOURCE[$t]}
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $DEFS $INCS -c "$src" -o "build/fuzz/$t.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/fuzz/$t.o" build/fuzz/lsan_off.o $LIBS -o "$SRC/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS build/fuzz/standalone_main.o "build/fuzz/$t.o" build/fuzz/lsan_off.o $LIBS -o "$SRC/$t-standalone"
done

# 2) The unit tests, with the project's normal flags (no sanitizer, no fuzz instrumentation).
#    Debug build type keeps assert() live: the tests are assert-based.
#    The pinned nng renamed SUCCESS to NNG_MQTT_SUCCESS but the upstream tests still say SUCCESS;
#    alias it for the test compiles only (no source edits). acl_deny_action_test is not built: it asserts
#    rc == BANNED and fails on unmodified upstream at this commit.
TEST_CFLAGS="$COVERAGE_FLAGS -DSUCCESS=NNG_MQTT_SUCCESS"
cmake -S . -B build/tests "${COMMON_CMAKE[@]}" -DNANOMQ_TESTS=ON -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$TEST_CFLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
ninja -C build/tests -j"$MAYHEM_JOBS" \
  sub_handler_test unsub_handler_test pub_handler_test hashmap_test

# 3) Known-answer probe (mayhem/selftest.c) against the normal-flag library.
$CC $COVERAGE_FLAGS -g $DEFS $INCS mayhem/selftest.c build/tests/nanomq/libnanomq.a build/tests/nng/libnng.a \
  -lm -lpthread -o build/tests/mayhem_selftest
