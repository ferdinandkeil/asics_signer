/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Schluessel-HAL. Der private Schluessel verlaesst das Backend nie.
 * Alle Backends (Light/NVS, SE-Stub, spaeter TPM) implementieren diese Schnittstelle.
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/** Backend initialisieren. */
esp_err_t asics_key_init(void);
/** true, wenn ein Schluessel vorhanden ist. */
bool asics_key_has_key(void);
/** Schluessel erzeugen. Bei vorhandenem Schluessel: ESP_ERR_INVALID_STATE (nie ersetzen). */
esp_err_t asics_key_generate(void);
/** Oeffentlicher Schluessel, 65 Byte unkomprimiert (0x04||X||Y). */
esp_err_t asics_key_get_public(uint8_t pub[65]);
/** SHA-256-Digest (32 Byte) signieren -> DER-kodierter ECDSA-Sig-Value (SEQUENCE{r,s}). */
esp_err_t asics_key_sign_digest(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len);

/** Adapter von asics_key_sign_digest() auf asics_sign_fn_t (cades_params_t.sign / csr_params_t.sign); ctx ungenutzt. */
esp_err_t asics_key_sign_adapter(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len, void *ctx);
