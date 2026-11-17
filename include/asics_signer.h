/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * ASiC-S Signaturkomponente (ETSI EN 319 162-1) - oeffentliche API.
 *
 * Erzeugt aus Nutzdaten im Arbeitsspeicher einen ASiC-S-Container
 * (ZIP, alle Eintraege STORE) mit CAdES-B-B Detached-Signatur
 * (EN 319 122-1, SHA-256 / ECDSA P-256). Die Nutzdaten bleiben bitgenau.
 *
 * Thread-Sicherheit: Die Funktionen sind nicht reentrant; die Anwendung
 * serialisiert Aufrufe (insbesondere asics_sign gegen die Konsole/Provisionierung).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Basis der komponentenspezifischen Fehlercodes. */
#define ASICS_ERR_BASE 0xA500
/** Zertifikat (DER/PEM) nicht parsebar. */
#define ASICS_ERR_CERT_PARSE        (ASICS_ERR_BASE + 1)
/** Oeffentlicher Schluessel des Geraetezertifikats passt nicht zum Geraeteschluessel. */
#define ASICS_ERR_CERT_KEY_MISMATCH (ASICS_ERR_BASE + 2)
/** Geraetezertifikat ist nicht von der angegebenen CA signiert. */
#define ASICS_ERR_CERT_CHAIN        (ASICS_ERR_BASE + 3)
/** Zertifikat ausserhalb seines Gueltigkeitszeitraums. */
#define ASICS_ERR_CERT_VALIDITY     (ASICS_ERR_BASE + 4)

/** Das Geraetezertifikat ist zum Signierzeitpunkt (aktuelle Zeit) nicht gueltig
 *  (noch nicht gueltig oder abgelaufen). asics_sign() verweigert die Signatur. */
#define ASICS_ERR_SIGNER_CERT_VALIDITY (ASICS_ERR_BASE + 5)

/** Ein DER-kodiertes Zertifikat (Zeiger + Laenge). */
typedef struct {
    const uint8_t *der;
    size_t len;
} asics_der_t;

/** Schreib-Callback fuer den streamenden Container-Ausgang.
 *  Rueckgabe != ESP_OK bricht die Erzeugung sofort ab und wird durchgereicht. */
typedef esp_err_t (*asics_write_cb_t)(const void *buf, size_t len, void *ctx);

/** Provisionierungszustand. */
typedef enum {
    ASICS_STATE_NO_KEY = 0,      /**< kein Geraeteschluessel */
    ASICS_STATE_KEY_NO_CERT,     /**< Schluessel vorhanden, Zertifikate fehlen */
    ASICS_STATE_PROVISIONED,     /**< signierbereit */
} asics_state_t;

/** Konfiguration fuer asics_signer_init(). */
typedef struct {
    /** Kundenspezifische Seriennummer fuer das CSR-Feld serialNumber
     *  (max. 64 Zeichen, PrintableString-Zeichensatz). NULL/leer = weglassen. */
    const char *device_serial;
} asics_config_t;

/**
 * Initialisiert Speicher und Schluessel-Backend. Erzeugt bei Bedarf (Kconfig
 * ASICS_AUTO_GENERATE_KEY) einmalig das Schluesselpaar. NVS muss zuvor von der
 * Anwendung initialisiert sein. cfg darf NULL sein.
 */
esp_err_t asics_signer_init(const asics_config_t *cfg);

/** Aktueller Provisionierungszustand. */
asics_state_t asics_signer_get_state(void);

/**
 * Signiert die Nutzdaten und schreibt den ASiC-S-Container streamend ueber write().
 * Reihenfolge im ZIP: mimetype, <payload_name>, META-INF/signature.p7s.
 *
 * @param payload_name Dateiname der Nutzdatei (ohne Pfad, 1..ASICS_PAYLOAD_NAME_MAX)
 * @param data         Nutzdaten (werden ohne Kopie gestreamt)
 * @param len          Laenge der Nutzdaten (< 4 GiB)
 *
 * Vor dem Signieren wird die Gueltigkeit (notBefore/notAfter) des Geraetezertifikats
 * gegen die aktuelle Zeit geprueft.
 *
 * @return ESP_OK; ESP_ERR_INVALID_STATE (nicht provisioniert / Uhrzeit < Mindestzeit /
 *         Uhrzeit nach 2107, ausserhalb des ZIP-DOS-Zeitbereichs 1980..2107);
 *         ASICS_ERR_SIGNER_CERT_VALIDITY (Geraetezertifikat nicht gueltig);
 *         ESP_ERR_INVALID_ARG; ESP_ERR_NO_MEM; oder der Fehler des Callbacks.
 */
esp_err_t asics_sign(const char *payload_name, const uint8_t *data, size_t len,
                     asics_write_cb_t write, void *ctx);

#ifdef __cplusplus
}
#endif
