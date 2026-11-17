/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include "key_backend.h"

esp_err_t asics_key_sign_adapter(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len, void *ctx)
{
    (void)ctx;
    return asics_key_sign_digest(digest, sig, sig_size, sig_len);
}
