/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* PEM-Hilfen (Base64 per mbedtls): kodieren, dekodieren, zeilenweiser Leser. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/** Mindestgroesse des Ausgabepuffers von asics_pem_encode() fuer len DER-Bytes (inkl. Terminator). */
size_t asics_pem_encoded_min_size(const char *label, size_t len);

/** DER -> PEM (nullterminiert, 64 Zeichen pro Zeile). ESP_ERR_NO_MEM bei zu kleinem Puffer. */
esp_err_t asics_pem_encode(const char *label, const uint8_t *der, size_t len,
                           char *out, size_t out_size, size_t *out_len);

/** Ersten PEM-Block mit label dekodieren. ESP_ERR_NOT_FOUND / ESP_ERR_INVALID_ARG. */
esp_err_t asics_pem_decode(const char *label, const char *pem, size_t pem_len,
                           uint8_t *der, size_t der_size, size_t *der_len);

/** Wie asics_pem_decode, aber ab *pos; *pos wird hinter den Block gesetzt (Bundle-Iteration).
 *  ESP_ERR_NOT_FOUND, wenn kein weiterer Block folgt. */
esp_err_t asics_pem_decode_next(const char *label, const char **pos, const char *end,
                                uint8_t *der, size_t der_size, size_t *der_len);

typedef enum { ASICS_PEM_NEED_MORE, ASICS_PEM_DONE, ASICS_PEM_ERROR } asics_pem_state_t;

typedef struct {
    char *buf; size_t cap; size_t len;
    const char *label;
    bool in_block;
} asics_pem_reader_t;

void asics_pem_reader_init(asics_pem_reader_t *r, char *buf, size_t cap, const char *label);
/**
 * true, wenn line (ohne Leerraum/Zeilenende) genau dem Steuerwort cmd entspricht UND der Leser sich
 * ausserhalb eines PEM-Blocks befindet. Innerhalb eines Blocks sind Zeilen immer Base64-Daten
 * (z. B. kann "abort" ein gueltiges Base64-Praefix sein).
 */
bool asics_pem_reader_is_command(const asics_pem_reader_t *r, const char *line, const char *cmd);

/** Eine Textzeile einspeisen; Zeilen vor BEGIN werden ignoriert. DONE nach END-Marker. */
asics_pem_state_t asics_pem_reader_feed(asics_pem_reader_t *r, const char *line);
