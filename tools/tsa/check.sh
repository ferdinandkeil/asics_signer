#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Integrationspruefung gegen die sigstore-Test-TSA (Docker):
#   1. Anfrage aus openssl (ts -query) -> TSA -> openssl ts -verify
#   2. Die von der Komponente erzeugte Anfrage (tsa_reply_request.tsq aus dem Host-Test) -> TSA ->
#      openssl ts -verify UND die Parser/Pruefung der Komponente (Host-Test test_tsa_external_response)
#
# Aufruf: tools/tsa/check.sh <pki-verzeichnis> <host-test-ausgabe> <host-test-elf> [port]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pki="${1:?PKI-Verzeichnis fehlt}"; out="${2:?Ausgabeverzeichnis des Host-Tests fehlt}"; elf="${3:?Host-Test-ELF fehlt}"
port="${4:-3000}"
url="http://127.0.0.1:$port/api/v1/timestamp"
work="$(mktemp -d)"
trap '"$here/run_tsa.sh" stop; rm -rf "$work"' EXIT

"$here/run_tsa.sh" start "$pki" "$port"

post() {  # post <anfrage> <antwort>: HTTP 200 und Content-Type application/timestamp-reply erwartet
  local ct
  ct="$(curl -sS -H 'Content-Type: application/timestamp-query' --data-binary "@$1" -o "$2" -w '%{http_code} %{content_type}' "$url")"
  [ "$ct" = "200 application/timestamp-reply" ] || { echo "FEHLER: TSA antwortet '$ct'" >&2; exit 1; }
}

echo "== 1. openssl-Anfrage"
echo "Testdaten" > "$work/data.txt"
openssl ts -query -data "$work/data.txt" -sha256 -cert -no_nonce -out "$work/o.tsq"
post "$work/o.tsq" "$work/o.tsr"
openssl ts -verify -data "$work/data.txt" -in "$work/o.tsr" -CAfile "$pki/tsa_root.pem"

echo "== 2. Anfrage der Komponente"
post "$out/tsa_reply_request.tsq" "$work/c.tsr"
openssl ts -verify -queryfile "$out/tsa_reply_request.tsq" -in "$work/c.tsr" -CAfile "$pki/tsa_root.pem"
ASICS_TEST_PKI="$pki" ASICS_TEST_OUT="$work" ASICS_TSA_EXT_REQUEST="$out/tsa_reply_request.tsq" \
  ASICS_TSA_EXT_RESPONSE="$work/c.tsr" "$elf" 2>&1 | tee "$work/unity.txt" | grep "test_tsa_external_response"
grep -q "test_tsa_external_response:PASS" "$work/unity.txt" || { echo "FEHLER: Pruefung der Komponente lehnt die Antwort ab" >&2; exit 1; }
echo "TSA-Integration OK"
