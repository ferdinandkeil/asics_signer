/*
 * ASiC-S Provisionierung: CSR-Erzeugung, Zertifikatsimport, Konsole.
 * Es gibt bewusst keine Funktion, die einen vorhandenen Schluessel setzt oder ersetzt.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "asics_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Setzt die Seriennummer fuer das CSR (serialNumber im Subject). NULL/"" = weglassen. */
esp_err_t asics_provision_set_serial(const char *serial);

/** Erzeugt den Schluessel, falls keiner existiert (sonst ESP_OK ohne Aenderung). */
esp_err_t asics_provision_ensure_key(void);

/** Liefert den oeffentlichen Schluessel (65 Byte, unkomprimiert 0x04||X||Y). */
esp_err_t asics_provision_get_public_key(uint8_t pub[65]);

/** Erzeugt den PKCS#10-CSR (DER). Subject: CN=Base-MAC, serialNumber, O, C. */
esp_err_t asics_provision_create_csr(uint8_t *der, size_t size, size_t *len);

/** Wie oben, PEM-kodiert (nullterminiert, len ohne Terminator). */
esp_err_t asics_provision_create_csr_pem(char *pem, size_t size, size_t *len);

/**
 * Importiert Geraetezertifikat und CA-Kette (DER).
 *
 * KETTENKONVENTION (definierte Reihenfolge): chain[0] ist die Issuing-CA (Aussteller des
 * Geraetezertifikats), chain[i+1] ist jeweils der Aussteller von chain[i]; das letzte
 * Glied darf eine selbstsignierte Root sein (optional). Die Kette hat 1..n Glieder;
 * insgesamt (Geraet + CAs) hoechstens CONFIG_ASICS_MAX_CHAIN Zertifikate.
 *
 * Geprueft werden: Public Key des Geraetezertifikats == Geraeteschluessel; Geraet von
 * chain[0] signiert, jede CA von der naechsten, alle CAs mit CA-Flag (selbstsigniertes
 * letztes Glied: Selbstsignatur); Gueltigkeit aller Zertifikate gegen die aktuelle Zeit.
 * Ist die Uhr ungueltig (< Mindestzeit), entfaellt NUR die Zeitpruefung (Log-Warnung).
 * Alle Zertifikate landen atomar im Speicher und (DER-sortiert) im CMS certificates-Set.
 *
 * Fehler: ASICS_ERR_CERT_PARSE/_KEY_MISMATCH/_CHAIN/_VALIDITY, ESP_ERR_INVALID_SIZE
 * (zu viele Zertifikate), ESP_ERR_NO_MEM (Kette passt nicht in CONFIG_ASICS_CMS_BUF_SIZE).
 */
esp_err_t asics_provision_import_der(const uint8_t *dev, size_t dev_len,
                                     const asics_der_t *chain, size_t chain_count);

/**
 * Wie oben mit PEM-Eingabe: dev_pem = ein CERTIFICATE-Block; chain_pem = Bundle aus 1..n
 * CERTIFICATE-Bloecken in der oben definierten Reihenfolge (Issuing-CA zuerst).
 * Beide nullterminiert.
 */
esp_err_t asics_provision_import_pem(const char *dev_pem, const char *chain_pem);

/** Registriert den Konsolenbefehl `asics` (status | csr | import).
 *  Nach esp_console_init()/REPL-Erzeugung aufrufen. Ohne Kconfig-Option: ESP_ERR_NOT_SUPPORTED. */
esp_err_t asics_console_register(void);

#ifdef __cplusplus
}
#endif
