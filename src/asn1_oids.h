/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Gemeinsame OBJECT-IDENTIFIER-Konstanten (nur Inhaltsbytes, ohne Tag/Laenge). */
#pragma once

#include <stdint.h>

extern const uint8_t ASN1_OID_SIGNED_DATA[9];
extern const uint8_t ASN1_OID_DATA[9];
extern const uint8_t ASN1_OID_SHA256[9];
extern const uint8_t ASN1_OID_ECDSA_SHA256[8];
extern const uint8_t ASN1_OID_CONTENT_TYPE[9];
extern const uint8_t ASN1_OID_MSG_DIGEST[9];
extern const uint8_t ASN1_OID_SIGNING_TIME[9];
extern const uint8_t ASN1_OID_SIGNING_CERT_V2[11];
extern const uint8_t ASN1_OID_CN[3];
extern const uint8_t ASN1_OID_SERIAL[3];
extern const uint8_t ASN1_OID_COUNTRY[3];
extern const uint8_t ASN1_OID_ORG[3];
extern const uint8_t ASN1_OID_EC_PUBKEY[7];
extern const uint8_t ASN1_OID_P256[8];
extern const uint8_t ASN1_OID_SIG_TIMESTAMP[11];
extern const uint8_t ASN1_OID_CT_TSTINFO[11];
extern const uint8_t ASN1_OID_SIGNING_CERT[11];
extern const uint8_t ASN1_OID_SHA1[5];
extern const uint8_t ASN1_OID_SHA384[9];
extern const uint8_t ASN1_OID_SHA512[9];
extern const uint8_t ASN1_OID_EXT_EKU[3];
extern const uint8_t ASN1_OID_KP_TIMESTAMPING[8];
