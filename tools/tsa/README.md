<!--
SPDX-FileCopyrightText: 2026 Ferdinand Keil
SPDX-License-Identifier: MIT
-->
# Test-TSA (sigstore/timestamp-authority)

Lokale RFC-3161-Zeitstempelautoritaet fuer Integrationstests der CAdES-B-T-Funktion, basierend auf dem
Docker-Image `ghcr.io/sigstore/timestamp-server` (v2.2.1, per Digest fixiert in `run_tsa.sh`). Der
`file`-Signer verwendet Schluessel und Kette der Test-PKI (`test/gen_test_pki.sh`: `tsa.key`, `tsa.pem`,
`tsa_root.pem`); die TSA ist **nur fuer Tests** gedacht.

```sh
tools/tsa/run_tsa.sh start <pki-verzeichnis> [port]   # http://127.0.0.1:3000/api/v1/timestamp
tools/tsa/run_tsa.sh stop
tools/tsa/check.sh <pki-verzeichnis> <host-test-ausgabe> <host-test-elf>   # Integrationspruefung
```

`check.sh` prueft (1) eine openssl-Anfrage gegen die TSA (`openssl ts -verify`) und (2) die von der Komponente
erzeugte Anfrage: Antwort per `openssl ts -verify` und durch Parser und Pruefung der Komponente
(Host-Test `test_tsa_external_response`, gesteuert ueber `ASICS_TSA_EXT_REQUEST`/`ASICS_TSA_EXT_RESPONSE`).
Voraussetzung: Docker mit Netz fuer den einmaligen Image-Pull; `curl`, `openssl`.
