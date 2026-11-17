# asics_signer - ASiC-S Signaturkomponente fuer ESP-IDF

Signiert Nutzdaten (z. B. CSV) aus dem RAM und liefert einen ASiC-S-Container
(ETSI EN 319 162-1) mit CAdES-B-B Detached-Signatur (EN 319 122-1, SHA-256, ECDSA P-256).
Ziel: ESP32, ESP-IDF >= 5.2.5 (mbedTLS 3.x).

## Container
ZIP, Reihenfolge: `mimetype` (STORE, kein Extra-Feld, Inhalt ab Offset 38), Nutzdatei,
`META-INF/signature.p7s`. Alle Eintraege STORE (keine Kompression, kein Data Descriptor,
kein ZIP64), eigener Writer, CRC32 via `esp_rom_crc32_le`. Die Schnittstelle in
`src/zip_writer.h` (zip_entry_t mit method/Groessen/CRC) erlaubt spaeter Kompression;
diese ist nicht implementiert. Ausgabe streamend ueber `asics_write_cb_t`, Nutzdaten ohne Kopie.

## Signatur
SignedData v1, ein SignerInfo (issuerAndSerialNumber), Zertifikate Geraet + Issuing-CA,
Zertifikate: Geraet + CA-Kette (1..n CAs, Gesamtzahl max. `CONFIG_ASICS_MAX_CHAIN`, Default 4), DER-sortiert im certificates-Set.
Signed Attributes: content-type, message-digest, signing-time (UTCTime bis 2049, danach
GeneralizedTime), signing-certificate-v2 (ESSCertIDv2/SHA-256 mit issuerSerial). SET OF
DER-sortiert. Hook fuer unsignedAttrs (`cades_params_t.unsigned_attrs`, spaeter B-T/TSA) vorhanden.

## Schluessel & Provisionierung
* HAL `src/backend/key_backend.h`; Backend per Kconfig: Light (NVS) oder SE-Stub (`ESP_ERR_NOT_SUPPORTED`).
* Ein vorhandener Schluessel wird nie ersetzt (weder API noch Konsole).
* Zustaende: `NO_KEY` -> `KEY_NO_CERT` -> `PROVISIONED`.
* Konsole: `asics status`, `asics csr` (PEM), `asics import`: zuerst das Geraetezertifikat (PEM) einfuegen, dann die CA-Zertifikate
  einzeln (Issuing-CA zuerst, Root zuletzt, optional), Abschluss mit der Zeile `end`; `abort` bricht ab.
* Kettenkonvention (API `asics_provision_import_der/_pem`): `chain[0]` = Issuing-CA, `chain[i+1]` = Aussteller von `chain[i]`; letztes Glied darf
  eine selbstsignierte Root sein. Bei PEM-Bundles gilt dieselbe Reihenfolge. Geprueft: Schluesselabgleich, Signaturkette, CA-Flag aller CAs,
  Gueltigkeit aller Zertifikate. Ist die Uhr ungueltig (< Mindestzeit), entfaellt nur die Zeitpruefung (Log-Warnung).
  Nicht geprueft: pathLen-Beschraenkungen, Sperrstatus.
* `asics_sign()` verweigert die Signatur mit `ASICS_ERR_SIGNER_CERT_VALIDITY`, wenn das Geraetezertifikat zum aktuellen Zeitpunkt nicht gueltig ist.
* Puffer: `CONFIG_ASICS_CMS_BUF_SIZE` muss Summe der Zertifikatslaengen + ca. 700 Byte fassen (Worst Case `MAX_CHAIN * CERT_MAX_LEN + 700`);
  der Import lehnt zu grosse Ketten mit `ESP_ERR_NO_MEM` ab.
* CSR: Subject C/O (Kconfig, optional), serialNumber (per `asics_config_t.device_serial`/`asics_provision_set_serial`), CN = Base-MAC (12 Hex).
* NVS muss von der Anwendung initialisiert werden; fuer Produktion `nvs_flash_secure_init` (nvs_keys, Flash Encryption) + Secure Boot v2.
  `CONFIG_ASICS_REQUIRE_FLASH_ENCRYPTION` verweigert die Schluesselerzeugung ohne aktive Flash Encryption.
* Zeit: `time()` muss >= `CONFIG_ASICS_MIN_TIME` (0 = Zeitpunkt des CMake-Laufs) sein, sonst `ESP_ERR_INVALID_STATE`.

## Tests
`test/host/run_tests.sh` (ESP-IDF aktivieren): baut die Unity-Testapp fuer das `linux`-Target, erzeugt per
`test/gen_test_pki.sh` eine Test-PKI (flache CA und Kette Root-Intermediate-Issuing-Geraet), fuehrt die Tests aus und prueft den Beispielcontainer mit
`unzip -t`, `zipinfo`, `openssl cms -verify [-cades]` und `openssl req -verify`.

Host-Build-Hinweise (ESP-IDF 5.2.5, linux-Target): die mbedtls-Komponente baut dort keine Quellen; die
Komponente kompiliert fuer den Host-Build `mbedtls/library/*.c` selbst mit (CMakeLists.txt). NVS wird durch
einen RAM-Speicher (`src/kv_ram.c`) ersetzt, nvs_flash wird auf dem Host nicht verwendet. `esp_rom_crc32_le`
und `esp_fill_random` existieren auf linux (der Zufall ist dort NICHT kryptografisch sicher - nur Tests).

## Validierung mit EU-DSS
`tools/verify_dss.sh <container.asics> <vertrauensanker.pem>` (Docker-Image `asics-dss` aus `tools/dss`). `run_tests.sh` ruft es auf, wenn Docker verfuegbar ist.

## Beispiel
`examples/basic_sign` (`idf.py set-target esp32 build`).
