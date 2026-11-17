# ASiC-S Signaturkomponente für ESP-IDF

Die **ASiC-S-Komponente (`asics_signer`)** ist ein gekapseltes ESP-IDF-Softwaremodul zur kryptografischen Absicherung einzelner Nutzdateien (z. B. CSV-Datensätze) nach dem europäischen Signaturstandard **ETSI EN 319 162** (*Associated Signature Containers – Simple*, *ASiC-S*).

## Zweck & Funktionsweise

Die Komponente nimmt rohe Nutzdaten aus dem Arbeitsspeicher entgegen, erzeugt eine binäre **CAdES-B-B Detached-Signatur** (ASN.1 DER-kodiert mit SHA-256 und ECDSA P-256) und verpackt beides zusammen in ein standardkonformes **`.asics`-ZIP-Archiv**. Die eigentliche Nutzdatei bleibt dabei bitgenau unverändert.

## Aufbau der erzeugten Container-Struktur

* **`mimetype`**: Unkomprimiert (`STORE`) als allererster ZIP-Eintrag abgelegt (`application/vnd.etsi.asic-s+zip`), damit Prüfsoftware den Container-Typ anhand der Magic Bytes sofort erkennt.
* **`<nutzdatei>.csv`**: Originaldaten, unkomprimiert (`STORE`).
* **`META-INF/signature.p7s`**: CAdES-Signatur, unkomprimiert (`STORE`), inklusive eingebetteter Zertifikatskette (Gerätezertifikat + Issuing-CA) sowie dem `signing-certificate-v2`-Attribut.

## Architektur & Merkmale

* **Hardware-Abstraktion über `Kconfig`:** Trennt die Container- und ASN.1-Erzeugung strikt vom Schlüssel-Backend. Unterstützt wahlweise die **Light-Variante** (Schlüssel im verschlüsselten NVS, abgesichert durch Secure Boot v2 und Flash Encryption) oder ein externes **Hardware-Security-Element / TPM 2.0** über identische Schnittstellen.
* **Zero-Touch-Provisioning:** Generiert bei Erstinbetriebnahme automatisch ein geräteindividuelles ECDSA-Schlüsselpaar über den Hardware-RNG des ESP32 und gibt einen PKCS#10-CSR zur Zertifizierung durch die Fertigungs-CA aus.
* **Provisioning über UART-Konsole** (`esp_console`, Fertigungsstation): CSR-Ausgabe als PEM, Import von Geräte- und CA-Zertifikat. CSR-Subject-DN: `CN` = Base-MAC aus eFuse (12 Hex-Zeichen ohne Trenner), `serialNumber` = Custom-Wert, den die Anwendung per API übergibt, `O`/`C` optional per Kconfig. Ein einmal erzeugter Schlüssel wird **nie neu gesetzt**: kein Ersetzen per Konsole oder API.
* **Minimale Abhängigkeiten:** Basiert ausschließlich auf den ESP-IDF-Bordmitteln (`mbedtls`, `nvs_flash`, `esp_rom` für CRC32). Das ZIP-Archiv wird von einem eigenen, schlanken Writer erzeugt (nur `STORE`, keine Kompressionsbibliothek); eine interne Schnittstelle erlaubt das spätere Nachrüsten von Kompression (z. B. uzlib) per Kconfig.
* **Zielplattform:** ESP32 (klassisch), ESP-IDF ≥ 5.2.5. Kein PSRAM vorausgesetzt.
* **Streaming-Ausgabe:** Der Container wird über einen Writer-Callback des Aufrufers ausgegeben (Datei, HTTP, Puffer).
* **Zeitquelle:** `signing-time` aus der Systemzeit; ohne gültige Uhrzeit wird die Signatur verweigert. CAdES-B-T mit TSA-Zeitstempel ist als spätere Erweiterung vorgesehen.

# Grundregeln für die Zusammenarbeit

1. **Erst fragen, dann implementieren.** Vor dem Schreiben von Code/YAML alle offenen Punkte klären (Entity-IDs, Zeiten, Werte, Bedingungen, Sonderfälle). Keine Platzhalter-Entwürfe auf Verdacht.
2. **Bei Unklarheiten strukturiert fragen – über das AskUserQuestion-Tool.** Fragen nicht als Fließtext stellen, sondern als Auswahlabfrage (max. 4 Fragen pro Runde, bei Bedarf mehrere Runden). Konkrete Optionen anbieten, empfohlene Option zuerst und mit „(Empfohlen)“ markieren. Reine Freitext-Angaben (z. B. Entity-IDs) über die „Other“-Eingabe abfragen.
3. **Bei Vorschlägen des Nutzers erst Feedback geben, dann implementieren.** Vorschlag bewerten (Vor-/Nachteile, Alternativen, Risiken) und auf Bestätigung warten, bevor etwas umgesetzt wird.
4. **Kleinteilig committen.** Ein Commit pro logischem Schritt (z. B. ein Modul samt zugehörigen Tests, eine Konfigurationsänderung, ein Tool). Keine Sammel-Commits über mehrere Themen. Jeder Commit soll für sich bauen und die Tests bestehen. Commit-Nachrichten auf Deutsch: kurze Betreffzeile im Imperativ, bei Bedarf Begründung im Text. Dateien gezielt stagen (kein `git add -A`).