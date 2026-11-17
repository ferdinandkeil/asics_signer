#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Startet/stoppt eine lokale RFC-3161-Test-TSA (sigstore/timestamp-authority, Docker) mit dateibasiertem
# Signer: Schluessel und Zertifikatskette stammen aus der Test-PKI (test/gen_test_pki.sh).
#
#   tools/tsa/run_tsa.sh start <pki-verzeichnis> [port]     (Standard-Port 3000, nur 127.0.0.1)
#   tools/tsa/run_tsa.sh stop
#
# Endpunkt: POST http://127.0.0.1:<port>/api/v1/timestamp  (application/timestamp-query)
# NUR fuer Tests: Der Signer-Schluessel liegt als Datei vor ("file"-Signer ist laut Hersteller nur fuer Tests).
set -euo pipefail

# Image per Digest fixiert (timestamp-server v2.2.1)
IMAGE="ghcr.io/sigstore/timestamp-server@sha256:32b970a783554af9ce9b4c7cd490a83cc6e915f3c3e344cc6f5d05a74d975d46"
NAME="asics-tsa"
STATE="${TMPDIR:-/tmp}/asics-tsa.dir"

case "${1:-}" in
  start)
    pki="${2:?PKI-Verzeichnis fehlt}"
    port="${3:-3000}"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    dir="$(mktemp -d)"
    echo "$dir" > "$STATE"
    cp "$pki/tsa.key" "$dir/tsa.key"
    cat "$pki/tsa.pem" "$pki/tsa_root.pem" > "$dir/chain.pem"   # Blatt zuerst, dann Root
    docker run -d --name "$NAME" --user "$(id -u):$(id -g)" -p "127.0.0.1:$port:3000" -v "$dir:/tsa:ro" "$IMAGE" \
      timestamp-server serve --host 0.0.0.0 --port 3000 --timestamp-signer file \
      --file-signer-key-path /tsa/tsa.key --certificate-chain-path /tsa/chain.pem \
      --disable-ntp-monitoring --enforce-intermediate-eku=false --include-chain-in-response=true >/dev/null
    for _ in $(seq 1 30); do
      curl -fs "http://127.0.0.1:$port/ping" >/dev/null 2>&1 && { echo "TSA laeuft: http://127.0.0.1:$port/api/v1/timestamp"; exit 0; }
      sleep 0.5
    done
    echo "TSA startete nicht:" >&2; docker logs "$NAME" >&2 || true; exit 1
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    [ -f "$STATE" ] && { rm -rf "$(cat "$STATE")"; rm -f "$STATE"; }
    ;;
  *)
    echo "Aufruf: $0 start <pki-verzeichnis> [port] | stop" >&2; exit 2 ;;
esac
