#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Validiert einen .asics-Container mit dem EU-DSS-basierten Docker-Image "asics-dss"
# gegen eine lokale Test-CA als Vertrauensanker. Offline (--network none).
# Exitcode 0 = TOTAL_PASSED.
#
# Aufruf: tools/verify_dss.sh <container.asics> <ca.pem>
#
# Das Image wird von tools/dss/ gebaut (nicht Teil dieses Skripts).
set -euo pipefail

# ---- Konfiguration (bei Bedarf anpassen) -----------------------------------
IMAGE="asics-dss"
# Offline-Policy aus tools/dss/policy (Sperrdaten-Pruefung des Signerzertifikats nur WARN, siehe tools/dss/README.md).
# Leer setzen fuer die unveraenderte DSS-Default-Policy.
POLICY_OPTS="--policy /app/policy/asics-offline-constraint.xml"
# ----------------------------------------------------------------------------

asics="${1:?Container (.asics) fehlt}"
ca="${2:?CA-Zertifikat (PEM) fehlt}"
root="$(cd "$(dirname "$0")/.." && pwd)"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" "$root/tools/dss"
fi

# Beide Dateien in ein temporaeres Datenverzeichnis legen (Mount nach /data)
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$asics" "$work/$(basename "$asics")"
cp "$ca" "$work/$(basename "$ca")"
mkdir -p "$work/out"

rc=0
# shellcheck disable=SC2086
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$work:/data" "$IMAGE" \
  --trust "/data/$(basename "$ca")" --report-dir /data/out $POLICY_OPTS \
  "/data/$(basename "$asics")" || rc=$?
report="$(cd "$(dirname "$asics")" && pwd)/dss-report"
rm -rf "$report"; cp -r "$work/out" "$report"
echo "Berichte: $report (Exitcode $rc)"
exit $rc
