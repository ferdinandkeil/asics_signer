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
    esp_err_t err;        /**< Ergebnis des TSA-Versuchs (ESP_OK = Token eingebettet) */
    bool embedded;
    time_t gen_time;
} tsa_hook_ctx_t;

/** cades_params_t.unsigned_attrs-Hook. REQUIRED: gibt Fehler zurueck (Abbruch); PREFERRED: schreibt bei Fehler
 *  nichts (-> B-B) und merkt sich den Grund in ctx->err. */
esp_err_t tsa_attr_hook(der_t *d, const uint8_t *sig, size_t sig_len, void *ctx);

/** Ob eine TSA-Verwendung grundsaetzlich konfiguriert ist (TSA-URL gesetzt); beeinflusst die Importpruefung. */
bool tsa_configured(void);
