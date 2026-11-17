/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * CAdES-B-B Detached (EN 319 122-1) als CMS ContentInfo/SignedData (DER).
 */
#pragma once

#include "asics_internal.h"
#include "asics_signer.h"
#include "der_writer.h"

/**
 * Hook fuer unsignedAttrs (spaeter z. B. signature-time-stamp fuer CAdES-B-T).
 * Schreibt die Attribute (jeweils komplette Attribute-SEQUENCE, rueckwaerts-
 * Konvention des der_writer) in d; cades_build() umschliesst sie mit [1] IMPLICIT.
 * Schreibt der Hook nichts, entfaellt unsignedAttrs ganz (kein leeres [1]).
 * Der Hook erhaelt die fertige Signatur (Eingabe fuer einen Zeitstempel).
 */
typedef esp_err_t (*cades_unsigned_attrs_cb_t)(der_t *d, const uint8_t *sig, size_t sig_len, void *ctx);

typedef struct {
    uint8_t payload_digest[ASICS_DIGEST_LEN]; /**< SHA-256 der Nutzdaten */
    time_t signing_time;
    const uint8_t *dev_cert; size_t dev_cert_len; /**< Geraetezertifikat (DER) */
    const asics_der_t *ca_certs; size_t ca_count; /**< CA-Kette (1..n, Issuing-CA zuerst) */
    asics_sign_fn_t sign; void *sign_ctx;
    cades_unsigned_attrs_cb_t unsigned_attrs; void *unsigned_ctx; /**< optional */
} cades_params_t;

/**
 * Baut die CMS-Struktur. Ergebnis liegt am Anfang von out (Laenge *out_len).
 * ESP_ERR_NO_MEM bei zu kleinem Puffer.
 */
esp_err_t cades_build(const cades_params_t *p, uint8_t *out, size_t out_size, size_t *out_len);
