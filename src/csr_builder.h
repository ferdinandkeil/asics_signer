/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* PKCS#10-CSR (RFC 2986), selbst mit asn1write kodiert, Signatur ueber HAL-Callback. */
#pragma once

#include "asics_internal.h"
#include "der_writer.h"

typedef struct {
    const char *cn;       /**< Common Name (Base-MAC, 12 Hex-Grossbuchstaben) */
    const char *serial;   /**< serialNumber, NULL/"" = weglassen */
    const char *org;      /**< O, NULL/"" = weglassen */
    const char *country;  /**< C (2 Buchstaben), NULL/"" = weglassen */
    uint8_t pub[ASICS_PUBKEY_LEN];
    asics_sign_fn_t sign; void *sign_ctx;
} csr_params_t;

/** Ergebnis (DER) liegt am Anfang von out. ESP_ERR_NO_MEM bei zu kleinem Puffer. */
esp_err_t csr_build(const csr_params_t *p, uint8_t *out, size_t out_size, size_t *out_len);
