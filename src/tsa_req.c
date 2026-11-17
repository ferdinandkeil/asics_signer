/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>
#include "tsa_req.h"
#include "der_writer.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "asn1_oids.h"

#define SEQ 0x30


esp_err_t asics_tsa_build_request(const uint8_t digest[32], const uint8_t nonce[ASICS_TSA_NONCE_LEN],
                                  const char *policy_oid, uint8_t *out, size_t size, size_t *len)
{
    if (!digest || !nonce || !out || !len) {
        return ESP_ERR_INVALID_ARG;
    }
    mbedtls_asn1_buf oid = {0};
    bool has_policy = policy_oid && policy_oid[0];
    if (has_policy && mbedtls_oid_from_numeric_string(&oid, policy_oid, strlen(policy_oid)) != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    der_t d;
    der_init(&d, out, size);
    size_t m_all = der_size(&d);
    der_bool(&d, true);                           /* certReq */
    der_uint_be(&d, nonce, ASICS_TSA_NONCE_LEN);  /* nonce */
    if (has_policy) {
        der_oid(&d, oid.p, oid.len);              /* reqPolicy */
    }
    {   /* messageImprint { AlgorithmIdentifier{sha256, NULL}, OCTET STRING } */
        size_t m = der_size(&d);
        der_octet_string(&d, digest, 32);
        size_t m_alg = der_size(&d);
        static const uint8_t null_val[] = {0x05, 0x00};
        der_raw(&d, null_val, sizeof(null_val));
        der_oid(&d, ASN1_OID_SHA256, sizeof(ASN1_OID_SHA256));
        der_wrap(&d, m_alg, SEQ);
        der_wrap(&d, m, SEQ);
    }
    der_int(&d, 1);                               /* version */
    der_wrap(&d, m_all, SEQ);
    free(oid.p);
    if (d.err) {
        return ESP_ERR_NO_MEM;
    }
    *len = der_size(&d);
    memmove(out, der_data(&d), *len);
    return ESP_OK;
}
