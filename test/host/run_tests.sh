#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Host-Tests bauen und ausfuehren, danach Container/CSR mit unzip/zipinfo/openssl pruefen
# und (falls Docker verfuegbar) mit EU-DSS validieren (tools/verify_dss.sh).
# Voraussetzung: ESP-IDF >= 5.2.5 aktiviert (. export.sh), openssl, unzip.
# Aufruf: test/host/run_tests.sh [arbeitsverzeichnis]
# Optional: ASICS_TSA_CHECK=1 fuehrt zusaetzlich tools/tsa/check.sh aus (sigstore-Test-TSA in Docker)
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
verify sample_tsa.asics "$pki/ca.pem"         # CAdES-B-T (PREFERRED): openssl prueft die CMS-Signatur
verify sample_tsa_required.asics "$pki/ca.pem"
for f in sample_tsa.asics sample_tsa_required.asics; do
  unzip -p "$f" META-INF/signature.p7s | openssl cms -cmsout -print -inform DER | grep -q "signatureTimeStampToken\|id-smime-aa-timeStampToken" \
    || { echo "FEHLER: $f enthaelt kein signature-time-stamp"; exit 1; }
done

echo "== openssl ts -query (TimeStampReq der Komponente)"
openssl ts -query -in tsa_request.tsq -text | tee tsa_request.txt
grep -q "Version: 1" tsa_request.txt && grep -q "Hash Algorithm: sha256" tsa_request.txt && \
  grep -q "Nonce: 0x0102030405060708" tsa_request.txt && grep -q "Certificate required: yes" tsa_request.txt && \
  grep -q "Policy OID: 1.2.3.4" tsa_request.txt || { echo "FEHLER: TimeStampReq nicht wie erwartet"; exit 1; }

echo "== openssl ts -reply (Antwort der Test-TSA)"
openssl ts -reply -in tsa_reply.tsr -text | tee tsa_reply.txt
grep -q "Status: Granted" tsa_reply.txt && grep -q "Nonce: 0x0102030405060708" tsa_reply.txt || { echo "FEHLER: TSA-Antwort unerwartet"; exit 1; }
openssl ts -verify -in tsa_reply.tsr -queryfile tsa_reply_request.tsq -CAfile "$pki/tsa_root.pem"

if [ -n "${ASICS_TSA_CHECK:-}" ]; then   # optional: Integration gegen die sigstore-Test-TSA (Docker, Image-Pull noetig)
  echo "== TSA-Integration (tools/tsa/check.sh)"
  "$repo/tools/tsa/check.sh" "$pki" "$ASICS_TEST_OUT" "$work/build/asics_host_test.elf"
fi

echo "== openssl req -verify"
openssl req -verify -noout -in device.csr.pem

echo "== EU-DSS-Validierung (tools/verify_dss.sh)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  "$repo/tools/verify_dss.sh" sample.asics "$pki/ca.pem"   # Fehlschlag bricht ab (set -e)
  echo "DSS: sample.asics TOTAL_PASSED"
  # B-T-Container: zwei Vertrauensanker (Geraete-CA und TSA-Root); Format muss CAdES-BASELINE-T sein
  for c in sample_tsa.asics sample_tsa_required.asics; do
    "$repo/tools/verify_dss.sh" "$c" "$pki/ca.pem" "$pki/tsa_root.pem" | tee "dss_$c.txt"
    grep -q "Format:         CAdES-BASELINE-T" "dss_$c.txt" && grep -q "Ergebnis:       TOTAL_PASSED" "dss_$c.txt" \
      || { echo "FEHLER: DSS meldet fuer $c nicht CAdES-BASELINE-T + TOTAL_PASSED"; exit 1; }
    echo "DSS: $c CAdES-BASELINE-T TOTAL_PASSED"
  done
  # Kettencontainer gegen die Root als Vertrauensanker; Fehlschlag bricht ab (set -e)
  for c in sample_chain.asics sample_chain3.asics; do
    "$repo/tools/verify_dss.sh" "$c" "$pki/root.pem"
    echo "DSS: $c TOTAL_PASSED"
  done
else
  echo "HINWEIS: Docker nicht verfuegbar/Daemon nicht erreichbar - DSS-Validierung UEBERSPRUNGEN (kein Fehlschlag)."
fi
