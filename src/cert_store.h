/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Zertifikatsspeicher (Geraetezertifikat + CA-Kette, DER), unabhaengig vom Key-Backend. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "esp_err.h"
#include "asics_signer.h"
#include "sdkconfig.h"

/** Maximale Blobgroesse (Header + alle Zertifikate) fuer asics_cert_store_load(). */
#define ASICS_CERT_BLOB_MAX \
    (1 + 2 * CONFIG_ASICS_MAX_CHAIN + CONFIG_ASICS_MAX_CHAIN * CONFIG_ASICS_CERT_MAX_LEN)

/**
 * Prueft und speichert (atomar als ein Blob "certs") Geraetezertifikat + Kette.
 * chain[0] = Aussteller des Geraetezertifikats, chain[i+1] = Aussteller von chain[i].
 *  - Public Key des Geraetezertifikats == Geraeteschluessel
 *  - Signaturkette (letztes Glied: bei Selbstsignatur gegen sich selbst), alle CA-Flags
 *  - Gueltigkeit aller Zertifikate zum Zeitpunkt now, falls check_time
 *  - das CMS (Probe-Build mit laengster Signatur) passt in CONFIG_ASICS_CMS_BUF_SIZE und
 *    CONFIG_ASICS_ATTRS_BUF_SIZE (beruecksichtigt auch lange Issuer-DNs)
 * Fehler: ASICS_ERR_CERT_PARSE/_KEY_MISMATCH/_CHAIN/_VALIDITY, ESP_ERR_INVALID_SIZE, ESP_ERR_NO_MEM.
 */
esp_err_t asics_cert_store_import(const uint8_t *dev, size_t dev_len,
                                  const asics_der_t *chain, size_t chain_count,
                                  bool check_time, time_t now);

/**
 * Laedt den Blob in buf (>= ASICS_CERT_BLOB_MAX). refs[0] = Geraet, refs[1..*count-1] = Kette;
 * Zeiger zeigen in buf. ESP_ERR_NOT_FOUND, wenn nichts gespeichert.
 */
esp_err_t asics_cert_store_load(uint8_t *buf, size_t buf_size, size_t *count,
                                asics_der_t refs[CONFIG_ASICS_MAX_CHAIN]);

/** true, wenn ein plausibler Zertifikatsblob vorhanden ist. */
bool asics_cert_store_present(void);

/** Prueft notBefore/notAfter eines DER-Zertifikats gegen now.
 *  ESP_OK, ASICS_ERR_CERT_PARSE oder ASICS_ERR_SIGNER_CERT_VALIDITY (mit Log-Meldung). */
esp_err_t asics_cert_check_validity(const uint8_t *der, size_t len, time_t now);
