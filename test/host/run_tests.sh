#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Host-Tests bauen und ausfuehren, danach Container/CSR mit unzip/zipinfo/openssl pruefen
# und (falls Docker verfuegbar) mit EU-DSS validieren (tools/verify_dss.sh).
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

cd "$ASICS_TEST_OUT"
echo "== unzip -t / zipinfo"
for f in sample.asics sample_chain.asics sample_chain3.asics; do unzip -t "$f"; done
zipinfo sample.asics

# verify <container> <Vertrauensanker>: CMS-Pruefung, CAdES-Pruefung, Negativtest
verify() {
  local f="$1" ca="$2" base="${1%.asics}"
  unzip -p "$f" META-INF/signature.p7s > "$base.p7s"
  echo "== openssl cms -verify: $f (Anker $(basename "$ca"))"
  openssl cms -verify -binary -inform DER -in "$base.p7s" -content messung.csv -CAfile "$ca" -out /dev/null
  echo "== openssl cms -verify -cades: $f (prueft signing-certificate-v2)"
  openssl cms -verify -cades -binary -inform DER -in "$base.p7s" -content messung.csv -CAfile "$ca" -out /dev/null
  (cat messung.csv; echo X) > messung_tampered.csv
  if openssl cms -verify -binary -inform DER -in "$base.p7s" -content messung_tampered.csv -CAfile "$ca" -out /dev/null 2>/dev/null; then
    echo "FEHLER: manipulierte Daten akzeptiert ($f)"; exit 1; else echo "Negativtest $f: abgelehnt (erwartet)"; fi
}
verify sample.asics "$pki/ca.pem"
verify sample_chain.asics "$pki/root.pem"     # Geraet + Issuing + Intermediate + Root
verify sample_chain3.asics "$pki/root.pem"    # Geraet + Issuing + Intermediate (Root nur als Anker)

echo "== openssl req -verify"
openssl req -verify -noout -in device.csr.pem

echo "== EU-DSS-Validierung (tools/verify_dss.sh)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  "$repo/tools/verify_dss.sh" sample.asics "$pki/ca.pem"   # Fehlschlag bricht ab (set -e)
  echo "DSS: sample.asics TOTAL_PASSED"
  # Kettencontainer gegen die Root als Vertrauensanker; Fehlschlag bricht ab (set -e)
  for c in sample_chain.asics sample_chain3.asics; do
    "$repo/tools/verify_dss.sh" "$c" "$pki/root.pem"
    echo "DSS: $c TOTAL_PASSED"
  done
else
  echo "HINWEIS: Docker nicht verfuegbar/Daemon nicht erreichbar - DSS-Validierung UEBERSPRUNGEN (kein Fehlschlag)."
fi
