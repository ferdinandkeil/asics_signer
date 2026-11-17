/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Zeitstempel-Integration: holt, prueft und bettet das TSA-Token als unsigned attribute ein. */
#pragma once

#include <stdbool.h>
#include <time.h>
#include "asics_signer.h"
#include "der_writer.h"

typedef struct {
    asics_tsa_mode_t mode;
    time_t now;           /**< Signierzeit (Geraeteuhr) */
    uint8_t *resp;        /**< Antwortpuffer (Heap, CONFIG_ASICS_TSA_MAX_RESP), vom Aufrufer verwaltet */
    const uint8_t *token; /**< geprueftes TimeStampToken (zeigt in resp), nach erfolgreichem tsa_fetch */
    size_t token_len;
    esp_err_t err;        /**< Ergebnis des TSA-Versuchs (ESP_OK = Token eingebettet) */
    bool embedded;
    time_t gen_time;
} tsa_hook_ctx_t;

/**
 * Holt und prueft ein Zeitstempel-Token fuer den Signaturwert sig (SHA-256 -> TimeStampReq -> Transport ->
 * Antwortpruefung). Laeuft bewusst ausserhalb von cades_build (flacher Stack). ESP_OK: c->token/token_len/gen_time
 * gesetzt; sonst ASICS_ERR_TSA_UNAVAILABLE/_REJECTED/_INVALID.
 */
esp_err_t tsa_fetch(tsa_hook_ctx_t *c, const uint8_t *sig, size_t sig_len);

/** cades_params_t.unsigned_attrs-Hook: schreibt das mit tsa_fetch geholte Token als signature-time-stamp.
 *  Kein Netzwerk, keine Pruefung. ESP_ERR_NO_MEM, wenn es nicht in den CMS-Puffer passt. */
esp_err_t tsa_embed_hook(der_t *d, const uint8_t *sig, size_t sig_len, void *ctx);

/** Ob eine TSA-Verwendung grundsaetzlich konfiguriert ist (TSA-URL gesetzt); beeinflusst die Importpruefung. */
bool tsa_configured(void);
