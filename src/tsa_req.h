/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * RFC 3161 TimeStampReq (nur Kodierung): Version 1, messageImprint SHA-256, Nonce, certReq TRUE,
 * optional reqPolicy.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define ASICS_TSA_NONCE_LEN 8

/**
 * Baut einen TimeStampReq (DER) fuer den SHA-256-Digest digest.
 * @param nonce       64-Bit-Nonce (Big Endian); wird als positiver INTEGER kodiert
 * @param policy_oid  optionale reqPolicy als Punktnotation ("1.2.3.4"), NULL/"" = weglassen
 * Ergebnis liegt am Anfang von out. ESP_ERR_NO_MEM bei zu kleinem Puffer, ESP_ERR_INVALID_ARG bei
 * ungueltiger OID.
 */
esp_err_t asics_tsa_build_request(const uint8_t digest[32], const uint8_t nonce[ASICS_TSA_NONCE_LEN],
                                  const char *policy_oid, uint8_t *out, size_t size, size_t *len);
