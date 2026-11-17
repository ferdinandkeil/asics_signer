# ASiC-S Signaturkomponente für ESP-IDF

Projektbeschreibung, Architektur, API, Kconfig und Testablauf stehen in der [README.md](README.md). Sie ist die
maßgebliche Dokumentation und wird bei Änderungen mitgepflegt.

## Verbindliche Festlegungen

Diese Entscheidungen sind getroffen und werden nicht ohne Rückfrage geändert:

* Ziel ESP32 (klassisch), ESP-IDF ≥ 5.2.5, kein PSRAM vorausgesetzt.
* ASiC-S nach ETSI EN 319 162-1. Signatur in `META-INF/signature.p7s`. Alle ZIP-Einträge STORE, eigener ZIP-Writer, keine Kompressionsbibliothek.
* CAdES-B-B detached, SHA-256 / ECDSA P-256. CAdES-B-T (RFC-3161-Zeitstempel) ist umgesetzt: TSA-Modus zur Laufzeit OFF/PREFERRED/REQUIRED, Transport `esp_http_client`, TSA-CA in die Firmware eingebettet.
* Ausgabe streamend über einen Writer-Callback.
* Ohne gültige Uhrzeit oder mit ungültigem Gerätezertifikat wird nicht signiert.
* Ein einmal erzeugter Geräteschlüssel wird nie neu gesetzt oder ersetzt.
* Nur ESP-IDF-Bordmittel als Abhängigkeiten der Firmware.
* Lizenz MIT. Neue Quelldateien erhalten den SPDX-Header (`SPDX-FileCopyrightText: 2026 Ferdinand Keil`, `SPDX-License-Identifier: MIT`). Ausgenommen sind die aus EU-DSS übernommenen Dateien in `tools/dss/policy/`.

## Prüfen vor dem Commit

`test/host/run_tests.sh` (ESP-IDF aktiviert) muss grün sein. Bei Änderungen an der Firmware muss außerdem `examples/basic_sign` für `esp32` ohne Warnungen bauen.

# Grundregeln für die Zusammenarbeit

1. **Erst fragen, dann implementieren.** Vor dem Schreiben von Code alle offenen Punkte klären (Werte, Schnittstellen, Bedingungen, Sonderfälle). Keine Platzhalter-Entwürfe auf Verdacht.
2. **Bei Unklarheiten strukturiert fragen, über das AskUserQuestion-Tool.** Fragen nicht als Fließtext stellen, sondern als Auswahlabfrage (max. 4 Fragen pro Runde, bei Bedarf mehrere Runden). Konkrete Optionen anbieten, empfohlene Option zuerst und mit „(Empfohlen)“ markieren. Reine Freitext-Angaben über die „Other“-Eingabe abfragen.
3. **Bei Vorschlägen des Nutzers erst Feedback geben, dann implementieren.** Vorschlag bewerten (Vor-/Nachteile, Alternativen, Risiken) und auf Bestätigung warten, bevor etwas umgesetzt wird.
4. **Kleinteilig committen.** Ein Commit pro logischem Schritt (z. B. ein Modul samt zugehörigen Tests, eine Konfigurationsänderung, ein Tool). Keine Sammel-Commits über mehrere Themen. Jeder Commit soll für sich bauen und die Tests bestehen. Commit-Nachrichten auf Deutsch: kurze Betreffzeile im Imperativ, bei Bedarf Begründung im Text. Dateien gezielt stagen (kein `git add -A`).
