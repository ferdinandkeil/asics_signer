#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Validiert einen .asics-Container mit dem EU-DSS-basierten Docker-Image "asics-dss"
# gegen eine lokale Test-CA als Vertrauensanker. Offline (--network none).
# Exitcode 0 = TOTAL_PASSED.
#
# Aufruf: tools/verify_dss.sh <container.asics> <anker.pem> [<weiterer-anker.pem> ...]
#   (B-T-Container: Geraete-CA/-Root und TSA-Root als Vertrauensanker angeben)
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
shift
[ "$#" -ge 1 ] || { echo "mindestens ein Vertrauensanker (PEM) erforderlich" >&2; exit 2; }
root="$(cd "$(dirname "$0")/.." && pwd)"

# Image immer (aus dem Docker-Cache) bauen: Policy und Code liegen im Image
docker build -q -t "$IMAGE" "$root/tools/dss" >/dev/null

# Container und Anker in ein temporaeres Datenverzeichnis legen (Mount nach /data)
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$asics" "$work/$(basename "$asics")"
trust=()
i=0
for ca in "$@"; do
  i=$((i + 1))
  cp "$ca" "$work/anchor$i.pem"
  trust+=(--trust "/data/anchor$i.pem")
done
mkdir -p "$work/out"

rc=0
# shellcheck disable=SC2086
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$work:/data" "$IMAGE" \
  "${trust[@]}" --report-dir /data/out $POLICY_OPTS \
  "/data/$(basename "$asics")" || rc=$?
report="$(cd "$(dirname "$asics")" && pwd)/dss-report"
rm -rf "$report"; cp -r "$work/out" "$report"
echo "Berichte: $report (Exitcode $rc)"
exit $rc
