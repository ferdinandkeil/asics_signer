/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "csr_builder.h"
#include "mbedtls/asn1.h"
#include "mbedtls/sha256.h"
#include "asn1_oids.h"

#define SEQ 0x30
#define SET 0x31


static bool printable_ok(const char *s)
{
    for (; *s; s++) {
        char c = *s;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              strchr(" '()+,-./:=?", c))) {
            return false;
        }
    }
    return true;
}

/* RDN: SET { SEQUENCE { type, value } } */
static void write_rdn(der_t *d, const uint8_t *oid, size_t oid_len, uint8_t tag, const char *v)
{
    size_t m = der_size(d);
    der_string(d, tag, v, strlen(v));
    der_oid(d, oid, oid_len);
    der_wrap(d, m, SEQ);
    der_wrap(d, m, SET);
}

esp_err_t csr_build(const csr_params_t *p, uint8_t *out, size_t out_size, size_t *out_len)
{
    if (!p || !p->cn || !p->cn[0] || !p->sign || !out || !out_len || p->pub[0] != 0x04) {
        return ESP_ERR_INVALID_ARG;
    }
    bool has_serial = p->serial && p->serial[0];
    bool has_org = p->org && p->org[0];
    bool has_c = p->country && p->country[0];
    if (strlen(p->cn) > 64 || (has_serial && (strlen(p->serial) > 64 || !printable_ok(p->serial))) ||
        (has_org && strlen(p->org) > 64) ||
        (has_c && (strlen(p->country) != 2 || !printable_ok(p->country)))) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t *tmp = malloc(out_size);
    if (!tmp) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = ESP_ERR_NO_MEM;

    /* CertificationRequestInfo in tmp (rueckwaerts) */
    der_t c;
    der_init(&c, tmp, out_size);
    size_t m_cri = der_size(&c);
    {   /* attributes [0] IMPLICIT SET OF - leer */
        size_t m = der_size(&c);
        der_wrap(&c, m, 0xA0);
    }
    {   /* SubjectPublicKeyInfo */
        size_t m = der_size(&c);
        der_bit_string(&c, p->pub, ASICS_PUBKEY_LEN);
        size_t m_alg = der_size(&c);
        der_oid(&c, ASN1_OID_P256, sizeof(ASN1_OID_P256));
        der_oid(&c, ASN1_OID_EC_PUBKEY, sizeof(ASN1_OID_EC_PUBKEY));
        der_wrap(&c, m_alg, SEQ);
        der_wrap(&c, m, SEQ);
    }
    {   /* Subject: C, O, serialNumber, CN (Reihenfolge im DER = Schreibreihenfolge rueckwaerts) */
        size_t m = der_size(&c);
        write_rdn(&c, ASN1_OID_CN, sizeof(ASN1_OID_CN), MBEDTLS_ASN1_UTF8_STRING, p->cn);
        if (has_serial) {
            write_rdn(&c, ASN1_OID_SERIAL, sizeof(ASN1_OID_SERIAL), MBEDTLS_ASN1_PRINTABLE_STRING, p->serial);
        }
        if (has_org) {
            write_rdn(&c, ASN1_OID_ORG, sizeof(ASN1_OID_ORG), MBEDTLS_ASN1_UTF8_STRING, p->org);
        }
        if (has_c) {
            write_rdn(&c, ASN1_OID_COUNTRY, sizeof(ASN1_OID_COUNTRY), MBEDTLS_ASN1_PRINTABLE_STRING, p->country);
        }
        der_wrap(&c, m, SEQ);
    }
    der_int(&c, 0); /* version v1 */
    der_wrap(&c, m_cri, SEQ);
    if (c.err) {
        goto done;
    }

    uint8_t digest[32];
    mbedtls_sha256(der_data(&c), der_size(&c), digest, 0);
    uint8_t sig[ASICS_SIG_MAX_LEN];
    size_t sig_len = 0;
    err = p->sign(digest, sig, sizeof(sig), &sig_len, p->sign_ctx);
    if (err != ESP_OK) {
        goto done;
    }
    err = ESP_ERR_NO_MEM;

    der_t d;
    der_init(&d, out, out_size);
    size_t m_all = der_size(&d);
    der_bit_string(&d, sig, sig_len);
    {
        size_t m = der_size(&d);
        der_oid(&d, ASN1_OID_ECDSA_SHA256, sizeof(ASN1_OID_ECDSA_SHA256));
        der_wrap(&d, m, SEQ);
    }
    der_raw(&d, der_data(&c), der_size(&c));
    der_wrap(&d, m_all, SEQ);
    if (d.err) {
        goto done;
    }
    *out_len = der_size(&d);
    memmove(out, der_data(&d), *out_len);
    err = ESP_OK;
done:
    free(tmp);
    return err;
}
