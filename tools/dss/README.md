# asics-dss – Offline-Validator für ASiC-S/CAdES (EU-DSS)

Kleine Java-CLI auf Basis der EU-Bibliothek DSS (`eu.europa.ec.joinup.sd-dss`, **6.5.1**, Java 21),
um von `asics_signer` erzeugte `.asics`-Container unabhängig zu prüfen.
Validierung strikt offline: nur die per `--trust` übergebene CA ist Trust Anchor; keine
OCSP/CRL/AIA-Abrufe, kein LOTL/TSL (kein Data-Loader konfiguriert, Container läuft mit `--network none`).

## Build

```sh
cd tools/dss
docker build -t asics-dss .      # Netz nur hier (Maven Central)
```
Basis-Images per Digest fixiert (`maven:3.9-eclipse-temurin-21`, `eclipse-temurin:21-jre`); Image ca. 340 MB.
Module: dss-asic-cades, dss-validation, dss-cms-object, dss-utils-apache-commons, dss-policy-jaxb, slf4j-simple.

## Aufruf

```sh
docker run --rm --network none --user $(id -u):$(id -g) -v <dir>:/data asics-dss \
    --trust /data/ca.pem \
    [--policy /app/policy/asics-offline-constraint.xml] \
    [--report-dir /data/out] /data/datei.asics
```
* `--trust` mehrfach möglich (PEM, auch mehrere Zertifikate je Datei).
* `--policy`: eigene Policy-XML. Ohne Angabe gilt die DSS-Default-Policy. Im Image liegen
  `/app/policy/default-constraint.xml` (Original DSS 6.5.1) und `/app/policy/asics-offline-constraint.xml`.
  Eigene Policy: Datei in `<dir>` legen und `/data/...` angeben.
* `--report-dir`: schreibt `simple-report.xml`, `detailed-report.xml`, `diagnostic-data.xml`,
  `etsi-validation-report.xml`. `--user` ist nötig, damit das (nicht-root) Container-Konto in das
  gemountete Verzeichnis schreiben darf.
* Ausgabe (stdout): Containertyp, MIME-Type, Indication/SubIndication, Signaturformat,
  signierte Dateien, Fehler/Warnungen. DSS-Logmeldungen (WARN) gehen auf stderr.
* Exitcode: 0 = TOTAL_PASSED, 1 = nicht bestanden, 2 = Aufruf-/Verarbeitungsfehler.

## Policy `policy/asics-offline-constraint.xml`

Kopie der DSS-6.5.1-Default-Policy (`policy/constraint.xml` aus `dss-policy-jaxb`, unverändert als
`default-constraint.xml` mitgeführt). Alle Änderungen sind mit `<!-- ASICS-OFFLINE: war ... -->` markiert. Revocation (je zwei Änderungen) in
`SignatureConstraints/BasicSignatureConstraints/SigningCertificate` und `.../CACertificate` (Diff: `diff policy/default-constraint.xml policy/asics-offline-constraint.xml`):


| Constraint | Default | hier | Grund |
|---|---|---|---|
| `RevocationDataAvailable` | FAIL | WARN | CAdES-B-B enthält keine Sperrinformationen, offline gibt es keine; Default liefert sonst INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `AcceptableRevocationDataFound` | FAIL | WARN | s. o. |

Die beiden Constraints sind im Abschnitt `CACertificate` ebenfalls auf WARN gesetzt: Bei Ketten mit
Zwischen-CAs (Gerät → Issuing → Intermediate → Root) fehlen offline auch für die CA-Zertifikate die
Sperrdaten; sonst INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE.

Zusätzlich auf **FAIL** gesetzt (vorher WARN) in `SignatureConstraints/SignedAttributes`, damit die
signing-certificate-v2-Bindung (Signatur <-> Gerätezertifikat) erzwungen wird:

| Constraint | Default | hier |
|---|---|---|
| `SigningCertificatePresent` | WARN | FAIL |
| `UnicitySigningCertificate` | WARN | FAIL |
| `SigningCertificateRefersCertificateChain` | WARN | FAIL |
| `SigningCertificateDigestAlgorithm` | WARN | FAIL |
| `IssuerSerialMatch` | WARN | FAIL |

`CertDigestPresent` und `CertDigestMatch` stehen im Default bereits auf FAIL. `KeyIdentifierMatch` bleibt WARN
(betrifft die SignerIdentifier-Form, nicht die signing-certificate-v2-Referenz). Die Änderungen im
Counter-Signature-Abschnitt wurde nicht verändert.

Im Abschnitt `Timestamp` (Signaturzeitstempel der B-T-Container) sind `RevocationDataAvailable` und
`AcceptableRevocationDataFound` des **TSA-Signerzertifikats** (`Timestamp/BasicSignatureConstraints/SigningCertificate`)
ebenfalls FAIL -> WARN (`<!-- ASICS-OFFLINE: war FAIL -->`): Eine TSA-Signatur wird offline ohne Sperrdaten geprüft, sonst
INDETERMINATE. Die CA-Zertifikate der TSA-Kette sind dort im Default bereits WARN. Der Zeitstempel selbst
(`MessageImprintDataFound/Intact`, Signatur, EKU, Kette zur `--trust`-Wurzel) wird weiterhin hart geprüft.
Für B-T-Container sind **zwei** Vertrauensanker nötig (Geräte-CA und TSA-Root): `--trust` mehrfach angeben.

Bewusst unverändert: `RevocationFreshness` (Default bereits IGNORE), `NotRevoked`/`NotOnHold` (FAIL, greifen,
sobald Sperrdaten vorliegen), die übrigen CA-Zertifikat-Constraints (u. a. `NotExpired`, CA-Flag, Signatur),
sowie alle Signatur-/Format-/Kryptoprüfungen (`SignatureIntact`, `ReferenceDataIntact`, `ReferenceDataExistence`,
`ProspectiveCertificateChain`, `Cryptographic`/Algorithmen, `NotExpired` usw.).

## Tests / Ergebnisse (Referenzcontainer, Test-CA)

| Container | Policy | Ergebnis |
|---|---|---|
| `test.asics` | Default | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE ("No revocation data found"), Exit 1 |
| `test.asics` | asics-offline | TOTAL_PASSED, CAdES-BASELINE-B, ASiC-S, `messung.csv`, Exit 0 |
| `test-tampered.asics` | asics-offline | TOTAL_FAILED / HASH_FAILURE, Exit 1 |
| `neg-control.asics` (BC-erzeugt, korrekte signing-certificate-v2) | asics-offline | TOTAL_PASSED (Kontrolle) |
| `neg-wronghash.asics` (Signatur gültig, signing-certificate-v2-Hash zeigt auf CA statt Gerätezertifikat) | asics-offline | INDETERMINATE / SIG_CONSTRAINTS_FAILURE, Exit 1 (mit altem WARN-Stand: TOTAL_PASSED) |
| `neg-wrongserial.asics` (Hash korrekt, issuerSerial falsch) | asics-offline | INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND ("'issuer-serial' attribute does not match"), Exit 1 (mit altem Stand: TOTAL_PASSED) |
| `test.asics` mit fremder CA | asics-offline und Default | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND, Exit 1 |

## Grenzen

* Keine Prüfung von Sperrinformationen, Zeitstempeln, Langzeitformaten (B-T/B-LT/B-LTA) oder
  Trusted Lists (Hinweis "Unable to build a certificate chain up to a trusted list" ist die
  Qualifikationsbewertung (eIDAS) und für diese Test-PKI erwartungsgemäß).
* TOTAL_PASSED bedeutet daher: Signatur kryptografisch korrekt, Kette bis zur übergebenen CA – nicht: Zertifikat nicht gesperrt.
* Validierungszeit = aktuelle Systemzeit (Zertifikatsgültigkeit wird dagegen geprüft).
* Berücksichtigt wird nur `--trust`; Zwischenzertifikate müssen im Container (`signature.p7s`) liegen oder in `--trust`.
