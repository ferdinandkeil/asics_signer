#!/usr/bin/env bash
# Host-Tests (Unity, linux-Target) bauen und ausfuehren.
# Voraussetzung: ESP-IDF >= 5.2.5 aktiviert (. export.sh), openssl, unzip.
# Aufruf: test/host/run_tests.sh [arbeitsverzeichnis]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="${1:-/tmp/asics_host_test}"
mkdir -p "$work"
export ASICS_TEST_PKI="$work/pki" ASICS_TEST_OUT="$work/out"
mkdir -p "$ASICS_TEST_OUT"
"$here/../gen_test_pki.sh" "$ASICS_TEST_PKI" >/dev/null
pki="$ASICS_TEST_PKI"

cd "$here"
idf_opts=(-B "$work/build" "-DSDKCONFIG=$work/sdkconfig")
[ -f "$work/sdkconfig" ] || idf.py "${idf_opts[@]}" --preview set-target linux
idf.py "${idf_opts[@]}" build
"$work/build/asics_host_test.elf"
