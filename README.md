# asics_signer: ASiC-S Signing Component for ESP-IDF

`asics_signer` is a self-contained ESP-IDF component that signs a single payload file (for example a CSV
record) held in RAM and emits a standards-compliant **ASiC-S container** (ETSI EN 319 162-1) with a
detached **CAdES-B-B signature** (ETSI EN 319 122-1, SHA-256 / ECDSA P-256), optionally extended to
**CAdES-B-T** with an RFC 3161 time stamp. The payload is stored bit-for-bit unchanged.

* **Target:** ESP32 (classic), ESP-IDF ≥ 5.2.5 (mbedTLS 3.x), no PSRAM required
* **Dependencies:** ESP-IDF only (`mbedtls`, `nvs_flash`, `esp_rom`, `console`), no third-party libraries
* **Output:** streamed through a caller-supplied write callback (file, HTTP, buffer)
* **Keys:** device-unique ECDSA P-256 key generated on first boot, never leaves the key backend and
  is never replaced
* **Provisioning:** PKCS#10 CSR and certificate import via the UART console (manufacturing station)

## Contents

- [Container layout](#container-layout)
- [Signature profile](#signature-profile)
- [Architecture](#architecture)
- [Requirements and integration](#requirements-and-integration)
- [Usage](#usage)
- [Time stamps (CAdES-B-T)](#time-stamps-cades-b-t)
- [Provisioning](#provisioning)
- [Configuration (Kconfig)](#configuration-kconfig)
- [Production security](#production-security)
- [Testing and validation](#testing-and-validation)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Authors](#authors)
- [License](#license)

## Container layout

The container is a ZIP archive with exactly three entries, in this order:

| # | Entry | Method | Content |
|---|-------|--------|---------|
| 1 | `mimetype` | STORE | `application/vnd.etsi.asic-s+zip` with no extra field, so the content starts at byte offset 38 (magic-byte detection) |
| 2 | `<payload_name>` | STORE | the payload, unchanged |
| 3 | `META-INF/signature.p7s` | STORE | DER-encoded CMS `SignedData` (CAdES-B-B, or B-T with a time stamp; detached) |

All entries are uncompressed. Sizes and CRC32 are known before each local header is written, so
no data descriptors and no ZIP64 records are used. CRC32 comes from the ROM (`esp_rom_crc32_le`).
The DOS timestamp of all entries equals the signing time. It can only represent 1980..2107; `asics_sign()` therefore refuses to sign (`ESP_ERR_INVALID_STATE`) when the clock is after 2107.

## Signature profile

`META-INF/signature.p7s` is a `ContentInfo` holding `SignedData` version 1:

* `digestAlgorithms`: SHA-256
* `encapContentInfo`: `id-data` without `eContent` (detached)
* `certificates`: device certificate plus the CA chain (1..n CAs), DER-sorted as required for a `SET OF`
* a single `SignerInfo` (version 1, `issuerAndSerialNumber`, `ecdsa-with-SHA256`)
* signed attributes, DER-sorted:
  * `content-type` (`id-data`)
  * `message-digest` (SHA-256 of the payload)
  * `signing-time` (`UTCTime` up to 2049, `GeneralizedTime` from 2050)
  * `signing-certificate-v2` (`ESSCertIDv2`, SHA-256, including `issuerSerial`)

The signature value is computed over the signed attributes re-tagged as `SET` (`0x31`), as
RFC 5652 requires. With a time stamp (see [Time stamps](#time-stamps-cades-b-t)) the `SignerInfo`
additionally carries the unsigned attribute `signature-time-stamp` (OID 1.2.840.113549.1.9.16.2.14),
which makes the signature CAdES-B-T.

## Architecture

The component is built in layers. Container and ASN.1 generation do not depend on where the private key
lives: everything that touches the key goes through a narrow hardware abstraction layer (HAL), and
everything that persists data goes through a small key/value store interface.

```
                ┌──────────────────────────────────────────────────────────────┐
 Application    │  asics_signer.h            asics_provision.h    UART console │
                │  asics_signer_init()       CSR / import / state  "asics …"   │
                │  asics_sign()                                   (optional)   │
                └──────────┬───────────────────────────┬───────────────────────┘
                           │                           │
                ┌──────────▼──────────┐   ┌────────────▼─────────────────────┐
 Orchestration  │ asics_signer.c      │   │ asics_provision.c                │
                │ state & time checks │   │ key creation, CSR, chain import  │
                │ cert validity check │   └───┬──────────────┬───────────────┘
                └──┬───────┬──────────┘       │              │
                   │       │                  │              │
       ┌───────────▼──┐ ┌──▼─────────────┐ ┌──▼──────────┐ ┌─▼────────────┐
 Format│ asics_       │ │ cades_builder  │ │ csr_builder │ │ cert_store   │
       │ container.c  │ │ CMS SignedData │ │ PKCS#10     │ │ chain blob,  │
       │ zip_writer.c │ │ signed attrs   │ │             │ │ checks       │
       └──────────────┘ └───────┬────────┘ └──────┬──────┘ └──────┬───────┘
                                │   der_writer.c  │               │
                                │   (mbedTLS asn1write)           │
                        ┌───────▼─────────────────▼────┐   ┌──────▼───────┐
 HAL                    │ key_backend.h                │   │ kv_store.h   │
                        │ generate / public / sign     │   │ get / set    │
                        └───────┬──────────────┬───────┘   └──┬────────┬──┘
                        ┌───────▼──────┐ ┌─────▼───────┐ ┌────▼───┐ ┌──▼────────┐
 Backends               │ backend_nvs  │ │ backend_se_ │ │ kv_nvs │ │ kv_ram    │
                        │ (Light)      │ │ stub        │ │ target │ │ host test │
                        └──────────────┘ └─────────────┘ └────────┘ └───────────┘
```

### Modules

| Module | Responsibility |
|--------|----------------|
| `include/asics_signer.h` | Public API: initialisation, provisioning state, `asics_sign()`, error codes |
| `include/asics_provision.h` | Public provisioning API: serial number, key creation, public key, CSR (DER/PEM), chain import (DER/PEM), console registration |
| `src/asics_signer.c` | Orchestrates signing: checks arguments, state and clock, loads the chain, checks the validity of the device certificate and every CA certificate (the device certificate is parsed once and reused by the CAdES builder), calls the CAdES builder and the container writer |
| `src/asics_provision.c` | Provisioning logic and the state machine (`NO_KEY → KEY_NO_CERT → PROVISIONED`) |
| `src/asics_container.c`, `src/zip_writer.c` | Streams the ASiC-S ZIP (local headers, central directory, end record) through the write callback; the payload is passed through without copying |
| `src/cades_builder.c` | Builds the CMS `SignedData` and signed attributes; signs through a callback that reaches the HAL |
| `src/der_writer.c` | Thin DER helpers on top of `mbedtls/asn1write.h` (DER `SET OF` sorting, time encoding) |
| `src/csr_builder.c` | Encodes the PKCS#10 CSR itself and signs it through the HAL. `mbedtls_x509write_csr` is not used because it needs the private key, which a secure element would never release |
| `src/cert_store.c` | Stores the device certificate and CA chain as one atomic blob; checks the key match, chain signatures, CA flags and validity periods |
| `src/tsa.c` | Time-stamp integration: nonce, request, transport, verification and embedding as unsigned attribute; TSA mode handling |
| `src/tsa_req.c`, `src/tsa_resp.c`, `src/tsa_verify.c`, `src/der_reader.h` | RFC 3161 request encoder, response / `TSTInfo` parser with content checks, token signature and TSA certificate checks, bounded DER reader |
| `src/tsa_transport.h`, `src/tsa_http.c`, `src/tsa_host.c` | Internal transport seam (not public API): `esp_http_client` on the target, `openssl ts -reply` with test hooks on the host |
| `src/time_source.c` | Clock validity: `time()` must be ≥ `CONFIG_ASICS_MIN_TIME` (the build time by default) |
| `src/pem_util.c` | PEM ↔ DER conversion for the CSR, the import and the console |
| `src/backend/key_backend.h`, `key_backend.c` | Key HAL: `init`, `has_key`, `generate`, `get_public`, `sign_digest`, plus the shared `asics_key_sign_adapter` used by the CAdES and CSR builders |
| `src/backend/backend_nvs.c` | Light backend: P-256 key in (encrypted) NVS, generated with the hardware RNG |
| `src/backend/backend_se_stub.c` | Placeholder for a secure element / TPM 2.0 (returns `ESP_ERR_NOT_SUPPORTED`) |
| `src/kv_store.h`, `src/kv_nvs.c`, `src/kv_ram.c` | Blob storage: NVS on the target, RAM for host tests |
| `src/console/asics_console.c` | `asics status`, `asics csr`, `asics import` (`esp_console`) |

### Signing data flow

1. **Checks.** `asics_sign()` validates its arguments, requires `PROVISIONED` state and a valid clock,
   and refuses to sign if the device certificate is not valid at the current time.
2. **Hash.** It computes the SHA-256 of the payload.
3. **Signed attributes.** `cades_builder` encodes them, hashes them as a `SET` and asks the key backend
   for an ECDSA signature over that hash (`sign_digest`).
4. **Time stamp (optional).** Depending on the TSA mode the unsigned-attribute hook requests, verifies and
   embeds an RFC 3161 token over the signature value.
5. **CMS.** The `SignedData` is assembled in a fixed heap buffer (`CONFIG_ASICS_CMS_BUF_SIZE`).
6. **Container.** `asics_container` streams `mimetype`, the payload and `signature.p7s`, followed by the
   central directory and the end record, through the caller's callback in chunks of at most
   `CONFIG_ASICS_WRITE_CHUNK` bytes. A callback error aborts generation immediately and is returned to
   the caller.

Memory use is bounded by one heap allocation (certificate blob plus CMS buffer, about 9 KB with the
defaults) and is independent of the payload size.

### Provisioning state machine

```
 NO_KEY ──(asics_signer_init / ensure_key: generate once)──▶ KEY_NO_CERT
 KEY_NO_CERT ──(import device cert + CA chain, verified)──▶ PROVISIONED
```

A key that exists is **never** regenerated or replaced, neither through the API nor through the
console. Certificates are public data and are kept in NVS regardless of the key backend, so the HAL
stays minimal.

## Requirements and integration

* ESP-IDF ≥ 5.2.5, target `esp32`
* NVS initialised by the application before `asics_signer_init()`

Add the component to your project, for example as a directory under `components/` or through
`EXTRA_COMPONENT_DIRS`:

```cmake
set(EXTRA_COMPONENT_DIRS "path/to/asics_signer")
```

and declare the dependency in your component's `CMakeLists.txt` (`REQUIRES asics_signer`).

## Usage

```c
#include "asics_signer.h"

static esp_err_t write_cb(const void *buf, size_t len, void *ctx)
{
    FILE *f = ctx;
    return fwrite(buf, 1, len, f) == len ? ESP_OK : ESP_FAIL;
}

void sign_record(const uint8_t *csv, size_t csv_len)
{
    asics_config_t cfg = { .device_serial = "SN-000123" };   /* CSR serialNumber */
    ESP_ERROR_CHECK(asics_signer_init(&cfg));                /* generates the key once */

    if (asics_signer_get_state() != ASICS_STATE_PROVISIONED) {
        return;                                              /* provision first */
    }
    FILE *f = fopen("/data/record.asics", "wb");
    esp_err_t err = asics_sign("record.csv", csv, csv_len, write_cb, f);
    fclose(f);
}
```

Return values of `asics_sign()`:

| Code | Meaning |
|------|---------|
| `ESP_OK` | container written |
| `ESP_ERR_INVALID_STATE` | not provisioned, clock below `CONFIG_ASICS_MIN_TIME`, or clock after 2107 |
| `ASICS_ERR_SIGNER_CERT_VALIDITY` | the device certificate or a CA certificate of the stored chain is not yet valid or expired |
| `ESP_ERR_INVALID_ARG` | invalid name, data or callback |
| `ESP_ERR_NO_MEM` | buffer allocation failed |
| any other | error returned by the write callback |

The API is not reentrant; serialise calls (including against the console).

A complete example is in [`examples/basic_sign`](examples/basic_sign) (`idf.py set-target esp32 build`).

## Time stamps (CAdES-B-T)

`asics_sign_ex()` can embed an RFC 3161 time stamp as the unsigned attribute `signature-time-stamp`,
which turns the signature into **CAdES-B-T**. The mode is chosen at run time:

```c
typedef enum { ASICS_TSA_DEFAULT, ASICS_TSA_OFF, ASICS_TSA_PREFERRED, ASICS_TSA_REQUIRED } asics_tsa_mode_t;

asics_set_tsa_mode(ASICS_TSA_PREFERRED);       /* RAM only, not persisted */

asics_sign_result_t res;
esp_err_t err = asics_sign_ex("record.csv", csv, csv_len, write_cb, ctx, &res);
/* res.level: ASICS_LEVEL_B_B or ASICS_LEVEL_B_T; res.tsa_err: reason if no time stamp; res.tsa_gen_time */
```

| Mode | Behaviour |
|------|-----------|
| `ASICS_TSA_OFF` | plain CAdES-B-B, byte-for-byte the previous output; the TSA is never contacted |
| `ASICS_TSA_PREFERRED` | try the time stamp; on any TSA error produce a B-B container, return `ESP_OK`, `res.level = ASICS_LEVEL_B_B`, `res.tsa_err` = reason |
| `ASICS_TSA_REQUIRED` | on any TSA error produce **no** container and make **no** write-callback call; the error code is returned |

The initial mode is the Kconfig default (`OFF` unless configured otherwise). `ASICS_TSA_DEFAULT` (value 0)
means "use the Kconfig default": it is what `asics_signer_init(NULL)` and a zero-initialised
`asics_config_t.tsa_mode` select, and `asics_set_tsa_mode(ASICS_TSA_DEFAULT)` restores it, while `OFF`,
`PREFERRED` and `REQUIRED` override it explicitly. `asics_get_tsa_mode()` always returns the effective mode
(never `DEFAULT`); invalid values are rejected with `ESP_ERR_INVALID_ARG`.
`asics_sign()` is unchanged and equals `asics_sign_ex(..., NULL)`. Error codes:
`ASICS_ERR_TSA_UNAVAILABLE` (network, timeout, HTTP error, no URL or no TSA CA configured),
`ASICS_ERR_TSA_REJECTED` (PKIStatus is neither granted nor grantedWithMods) and `ASICS_ERR_TSA_INVALID`
(the response failed a check below, or exceeds `CONFIG_ASICS_TSA_MAX_RESP`).

**Request.** `TimeStampReq` v1 with `messageImprint` = SHA-256 over the octets of `SignerInfo.signature`,
a random 64-bit nonce (`esp_fill_random`), `certReq = TRUE` and an optional `reqPolicy` OID. It is sent
with `esp_http_client` as `POST` (`Content-Type: application/timestamp-query`) to `CONFIG_ASICS_TSA_URL`;
for `https://` URLs the mbedTLS certificate bundle is used if enabled. There is no public transport
callback. Redirects are not followed.

**Verification on the device** (all of it, before anything is embedded):

* PKIStatus `granted` or `grantedWithMods`; the token is a `SignedData` with `eContentType` `id-ct-TSTInfo`
  and exactly one `SignerInfo`
* `TSTInfo`: version 1, `messageImprint` (SHA-256 and value) and nonce match the request, `genTime` is within
  `CONFIG_ASICS_TSA_GENTIME_TOLERANCE_S` (default 300 s) of the device clock; if `CONFIG_ASICS_TSA_POLICY_OID` is set,
  `TSTInfo.policy` must equal it exactly
* signed attributes: `content-type` = `id-ct-TSTInfo`, `message-digest` over the `eContent`, and an ESS
  `signing-certificate` or `signing-certificate-v2` whose hash matches the TSA certificate in the token
* the `signatureAlgorithm` must be known and match the key type and the `digestAlgorithm`: `ecdsa-with-SHA256/384/512`,
  `rsaEncryption` / `sha256/384/512WithRSAEncryption` (PKCS#1 v1.5) or RSASSA-PSS (hash, MGF1 and salt length taken from the
  parameters, SHA-2 only); anything else is `ASICS_ERR_TSA_INVALID`. The signature is checked over the DER signed attributes
* the TSA certificate carries a **critical** extended key usage `timeStamping` and no other usage, chains up to
  the embedded TSA CA (the trust anchor, which needs the CA flag); further certificates in the token serve as
  untrusted intermediates, and every certificate of the chain must be valid at `genTime`

**Configuration.** Set `CONFIG_ASICS_TSA_URL` and `CONFIG_ASICS_TSA_CA_PEM`, the path of exactly one trusted
TSA CA as a PEM file (relative paths are relative to the project directory); it is embedded in the firmware.
The CA is decoded on the heap (no fixed size limit, so RSA-4096 roots are fine), parsed once on first use and cached. Without a TSA CA or URL no time stamp can be produced: `PREFERRED` falls back to B-B and `REQUIRED` fails with
`ASICS_ERR_TSA_UNAVAILABLE`. The application provides the network (for example Wi-Fi) and a clock accurate to
within the tolerance; the call blocks until the TSA answers or `CONFIG_ASICS_TSA_TIMEOUT_MS` expires.

**Buffers and memory.** With a TSA URL configured, `ASICS_CMS_BUF_SIZE` defaults to 9216 and the certificate
import runs its probe build with a token of `ASICS_TSA_MAX_RESP` bytes, so a chain that would not leave room
for the token is rejected at import time. While time-stamping, a call additionally allocates the response
buffer (`ASICS_TSA_MAX_RESP`, default 4096 bytes) and verification uses short-lived heap for the parsed TSA
and CA certificates (about 1 KB). An estimate for the default configuration with a TSA is about 25 KB of
heap (certificate blob 4 KB, CMS buffer 9 KB, response 4 KB, attribute scratch 1.5 KB, certificates and
mbedTLS state) plus the HTTP client; an `https://` TSA adds the TLS session (roughly 40 KB more). The
time stamp is requested after the signature has been computed and outside the CAdES builder: `asics_sign_ex()` builds
the CMS once, asks the TSA for a token over that signature and, if it got one, builds the CMS again with the same
signature value (replayed) plus the token. Large buffers (TSA response, TSA CA, certificates) are on the heap.
**Stack of the calling task** (estimates, to be measured on hardware): at least 4 KB with `OFF`, at least 8 KB with a
time stamp over `http://`, and at least 12 KB over `https://` (TLS handshake). The numbers are estimates: the
time-stamp path has not been run on hardware yet.

The example `examples/basic_sign` has the console commands `wifi <ssid> <password>`
(`WIFI_STORAGE_RAM`, nothing is stored), `tsa-mode off|preferred|required` and `sign`, which prints the
level, the TSA error and the `genTime`. Its `sdkconfig.defaults` leave the TSA URL and CA empty; set
`CONFIG_ASICS_TSA_URL="http://<host>/api/v1/timestamp"` and `CONFIG_ASICS_TSA_CA_PEM="tsa_ca.pem"` (a file next
to the example's `CMakeLists.txt`), for example through `idf.py menuconfig`.

## Provisioning

At the manufacturing station, over the UART console (`CONFIG_ASICS_ENABLE_CONSOLE`, registered by the
application with `asics_console_register()`):

1. `asics status` shows the state, public key and clock.
2. `asics csr` prints the PKCS#10 CSR as PEM. The subject is:
   * `C` and `O` (optional, from Kconfig)
   * `serialNumber` (the application-supplied `device_serial`)
   * `CN` (the base MAC from eFuse, 12 upper-case hex digits)
3. The manufacturing CA issues the device certificate.
4. `asics import`: paste the device certificate (PEM), then each CA certificate. The issuing CA comes
   first, each following certificate is the issuer of the previous one, and a self-signed root at the
   end is optional. Finish with the line `end`, or cancel with `abort` (both are only recognised outside a PEM block).

On import, the component checks:

* the certificate's public key matches the device key
* every link of the chain is signed by the next
* every CA certificate has the CA flag
* every certificate is within its validity period

If the clock is not yet valid, only the validity-period check is skipped (with a warning). It is then
enforced at signing time for the device certificate and every CA certificate of the chain. The API equivalents are `asics_provision_import_der()` and
`asics_provision_import_pem()`.

## Configuration (Kconfig)

Menu **ASiC-S Signer**:

| Option | Default | Description |
|--------|---------|-------------|
| `ASICS_KEY_BACKEND_NVS` / `_SE_STUB` | NVS | Key backend |
| `ASICS_NVS_PARTITION`, `ASICS_NVS_NAMESPACE` | `nvs`, `asics` | NVS location |
| `ASICS_AUTO_GENERATE_KEY` | y | Generate the key in `asics_signer_init()` |
| `ASICS_BOOTLOADER_RANDOM` | y | Wrap key generation in `bootloader_random_enable/disable` (true entropy without RF) |
| `ASICS_REQUIRE_FLASH_ENCRYPTION` | y | Refuse key generation unless flash encryption is active |
| `ASICS_MIN_TIME` | 0 | Minimum valid Unix time (0 = time of the CMake run) |
| `ASICS_CERT_MAX_LEN` | 1024 | Maximum DER size of one certificate |
| `ASICS_MAX_CHAIN` | 4 | Maximum certificates in total (device + CAs), range 2..8 |
| `ASICS_CMS_BUF_SIZE` | 5120 (9216 with a TSA URL) | CMS buffer; must hold the CMS (all certificates + attributes + signature); import verifies this with a probe build |
| `ASICS_ATTRS_BUF_SIZE`, `ASICS_CSR_BUF_SIZE` | 768, 768 | Work buffers |
| `ASICS_PAYLOAD_NAME_MAX` | 100 | Maximum payload file name length |
| `ASICS_WRITE_CHUNK` | 4096 | Maximum bytes per write-callback call |
| `ASICS_SUBJECT_ORG`, `ASICS_SUBJECT_COUNTRY` | empty | CSR subject `O` / `C` (omitted if empty) |
| `ASICS_ENABLE_CONSOLE` | y | Build the `asics` console command |
| `ASICS_TSA_URL` | empty | TSA endpoint (HTTP/HTTPS); empty = no time stamps possible |
| `ASICS_TSA_DEFAULT_OFF` / `_PREFERRED` / `_REQUIRED` | OFF | Initial TSA mode (changeable at run time) |
| `ASICS_TSA_CA_PEM` | empty | PEM file of the single trusted TSA CA, embedded in the firmware |
| `ASICS_TSA_POLICY_OID` | empty | `reqPolicy` OID in the request and required `TSTInfo.policy` of the answer (neither if empty) |
| `ASICS_TSA_TIMEOUT_MS` | 5000 | Timeout of the TSA request |
| `ASICS_TSA_MAX_RESP` | 4096 | Maximum TSA response / token size (heap) |
| `ASICS_TSA_GENTIME_TOLERANCE_S` | 300 | Allowed difference between `genTime` and the device clock |

## Production security

The Light backend relies on the ESP32 platform security features. For production:

* **Secure Boot v2**, which on the classic ESP32 requires chip revision v3.0 or later
* **Flash encryption** in release mode
* **NVS encryption** via `nvs_flash_secure_init()` with an `nvs_keys` partition protected by flash
  encryption. The classic ESP32 has no HMAC peripheral.
* Disable JTAG and the UART download mode, and disable `CONFIG_ASICS_ENABLE_CONSOLE` after
  provisioning

The component itself checks only that flash encryption is active
(`CONFIG_ASICS_REQUIRE_FLASH_ENCRYPTION`). Initialising NVS securely is the application's
responsibility. Key material in RAM is wiped with `mbedtls_platform_zeroize`.

## Testing and validation

```sh
. $IDF_PATH/export.sh
test/host/run_tests.sh [work-dir]
```

The host test suite builds a Unity test app for the ESP-IDF `linux` target and runs these steps:

1. It generates a test PKI (`test/gen_test_pki.sh`): a single issuing CA, a chain
   root → intermediate → issuing → device, and a test TSA (root CAs, an EC TSA certificate with critical
   `timeStamping` EKU, variants without EKU and from a foreign CA, an RSA TSA certificate).
2. It runs the unit tests: ZIP layout and offsets, CAdES determinism and attribute ordering, CSR,
   import checks, chain lengths, time and validity checks.
3. It checks the generated containers with:
   * `unzip -t` and `zipinfo`
   * `openssl cms -verify` (also with `-cades`), plus a tampered-payload test that must be rejected
   * `openssl req -verify` for the CSR, `openssl ts -query` / `-reply` / `-verify` for the time stamp
     request and the test TSA answer
4. If Docker is available, it validates the containers with **EU DSS**, including the CAdES-B-T
   containers, which must be reported as `CAdES-BASELINE-T` with `TOTAL_PASSED`. Otherwise this step is
   skipped with a notice.

The time stamp tests use `openssl ts -reply` as the test TSA (the host transport in `src/tsa_host.c`, with a test
hook) and cover both modes plus every failure class in `PREFERRED` and `REQUIRED`: transport error,
rejected status, wrong imprint, wrong nonce, tampered TSA signature, tampered `TSTInfo`, TSA certificate from a
foreign CA or without EKU, `genTime` outside the tolerance, truncated or oversized response, missing token and
missing TSA CA. `ASICS_TSA_CHECK=1 test/host/run_tests.sh` additionally runs
[`tools/tsa/check.sh`](tools/tsa), which checks a request of the component against the
[sigstore timestamp-authority](https://github.com/sigstore/timestamp-authority) in Docker (needs a one-time
image pull).

On the host, the RAM store replaces NVS and the random source is **not** cryptographically secure,
which is acceptable for tests only.

`tools/verify_dss.sh <container.asics> <trust-anchor.pem> [<more-anchors.pem> ...]` (a CAdES-B-T container needs the device CA and the TSA root) validates a container offline
(`--network none`) with the `asics-dss` Docker image built from [`tools/dss`](tools/dss) (DSS 6.5.1). Exit
code 0 means `TOTAL_PASSED`. The bundled offline policy lowers only the revocation-data checks (including those of the TSA signer certificate) to
warnings, because CAdES-B-B carries no revocation data and none is fetched offline. The
`signing-certificate-v2` checks are raised to FAIL. See [`tools/dss/README.md`](tools/dss/README.md)
(in German) for details.

### Hardware test

`examples/basic_sign` was tested on an ESP32-D0WD-V3 (chip revision v3.0, 4 MB flash, ESP-IDF 5.2.5).
Flash encryption was off and the key was stored in unencrypted NVS (development setup).

| Step | Result |
|------|--------|
| First boot with empty NVS | key generated in 444 ms |
| `asics csr` | CSR signature valid; `CN` matches the eFuse base MAC |
| Import of device certificate + single CA | accepted, state `PROVISIONED` |
| Import of device certificate + issuing → intermediate → root | accepted (re-import), 4 certificates embedded |
| Signing on the device, validation with EU DSS | `TOTAL_PASSED`, `CAdES-BASELINE-B` (single CA and chain) |
| Reset | no new key, same public key, chain retained |
| Signing after reset without setting the clock | refused with `ESP_ERR_INVALID_STATE` |

Measured with a 36-byte payload:

* `asics_sign()` takes about 236 ms, independent of chain length.
* Peak heap use is about 15 KB: about 9.2 KB is the fixed buffer, the rest is used by mbedTLS.
* The console task used about 3.6 KB of its 8 KB stack.
* The container is 1589 bytes with a single CA and 2405 bytes with the 4-certificate chain.

## Limitations and roadmap

* Secure element / TPM 2.0 backend: interface only (stub)
* No compression; the `zip_writer` interface allows adding it later (for example uzlib)
* No ZIP64 (payload < 4 GiB)
* CAdES-B-T: one embedded TSA CA, HTTP(S) transport only (no custom transport), no TSA certificate
  revocation checking, no long-term formats (B-LT, B-LTA); the HTTP transport has been compiled for the
  target but not run on hardware, and `https://` TSAs additionally depend on a certificate bundle in the
  application
* Not checked on import: `pathLen` constraints and revocation status
* Production security features (Secure Boot v2, flash encryption, NVS encryption) have not yet been
  tested together with the component on hardware

## Authors

Written by Claude (Anthropic) under the supervision of Ferdinand Keil.

## License

[MIT](LICENSE) © 2026 Ferdinand Keil.

Third-party material: the validation policies in `tools/dss/policy/` are derived from the default
policy of the [EU DSS](https://github.com/esig/dss) library and are subject to DSS's license
(LGPL-2.1), not MIT. The `asics-dss` Docker image is a test tool built from DSS. Neither is part of the
firmware component.
