/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Interne Typen und Konstanten (nicht oeffentlich). */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "esp_err.h"
#include "sdkconfig.h"

/** Signierfunktion: SHA-256-Digest (32 Byte) -> DER-kodierter ECDSA-Sig-Value. */
typedef esp_err_t (*asics_sign_fn_t)(const uint8_t digest[32], uint8_t *sig,
                                     size_t sig_size, size_t *sig_len, void *ctx);

/** true, wenn len in 32 Bit passt (kein ZIP64: Nutzdaten < 4 GiB). */
static inline bool asics_len_fits_u32(size_t len)
{
#if SIZE_MAX > 0xFFFFFFFFu
    return len <= 0xFFFFFFFFu;
#else
    (void)len;
    return true;
#endif
}

#define ASICS_DIGEST_LEN 32
#define ASICS_PUBKEY_LEN 65
#define ASICS_SIG_MAX_LEN 80 /* DER-ECDSA P-256: max. 72 Byte */

#define ASICS_MIMETYPE_NAME    "mimetype"
#define ASICS_MIMETYPE_VALUE   "application/vnd.etsi.asic-s+zip"
#define ASICS_SIGNATURE_NAME   "META-INF/signature.p7s"
