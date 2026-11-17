/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * RFC 3161 TimeStampResp / TimeStampToken / TSTInfo: Parser mit Inhaltspruefung
 * (Status, Version, messageImprint, Nonce, genTime). Signatur- und Zertifikatspruefung: tsa_verify.h.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "esp_err.h"
#include "der_reader.h"

typedef struct {
    const uint8_t *token;  /**< TimeStampToken (ContentInfo, komplettes TLV) innerhalb der Antwort */
    size_t token_len;
} tsa_resp_t;

/**
 * Prueft PKIStatusInfo und liefert den TimeStampToken.
 * ASICS_ERR_TSA_REJECTED: Status weder granted(0) noch grantedWithMods(1).
 * ASICS_ERR_TSA_INVALID: Struktur defekt/abgeschnitten, Token fehlt.
 */
esp_err_t tsa_parse_response(const uint8_t *resp, size_t len, tsa_resp_t *out);

typedef struct {
    const uint8_t *tstinfo;      /**< eContent (TSTInfo, DER) */
    size_t tstinfo_len;
    der_rd_t certs;              /**< Inhalt von certificates [0] (leer, wenn keine) */
    der_rd_t signer_info;        /**< Inhalt des (einzigen) SignerInfo */
} tsa_token_t;

/** Zerlegt ContentInfo/SignedData (eContentType id-ct-TSTInfo, genau ein SignerInfo). ASICS_ERR_TSA_INVALID. */
esp_err_t tsa_parse_token(const uint8_t *token, size_t len, tsa_token_t *t);

typedef struct {
    const uint8_t *digest;       /**< erwarteter messageImprint (SHA-256, 32 Byte) */
    const uint8_t *nonce;        /**< gesendete Nonce (Big Endian) */
    size_t nonce_len;
    time_t now;                  /**< Geraeteuhr */
    unsigned tolerance_s;        /**< zulaessige Abweichung genTime <-> now */
} tsa_expect_t;

/** Prueft TSTInfo (Version 1, Imprint SHA-256, Nonce, genTime-Toleranz); ASICS_ERR_TSA_INVALID. */
esp_err_t tsa_check_tstinfo(const uint8_t *tstinfo, size_t len, const tsa_expect_t *e, time_t *gen_time);

/** GeneralizedTime-Inhalt (YYYYMMDDHHMMSS[.f]Z) nach time_t (UTC); false bei Formatfehler. */
bool tsa_parse_generalized_time(const uint8_t *s, size_t len, time_t *out);
