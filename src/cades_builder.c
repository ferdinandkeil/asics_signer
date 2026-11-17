/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cades_builder.h"
#include "esp_log.h"
#include "mbedtls/asn1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform_util.h"
#include "asn1_oids.h"

static const char *TAG = "asics_cades";

/* OID-Inhaltsbytes */
/* id-aa-signingCertificateV2 = 1.2.840.113549.1.9.16.2.47 */

_Static_assert(CONFIG_ASICS_MAX_CHAIN <= DER_SET_MAX, "ASICS_MAX_CHAIN passt nicht in ein DER-SET (DER_SET_MAX)");

#define SEQ 0x30
#define SET 0x31

#define OID(d, o) der_oid((d), (o), sizeof(o))

/* AlgorithmIdentifier ohne Parameter (RFC 5754 bzw. RFC 5758 fuer ecdsa-with-SHA256). */
static void write_alg(der_t *d, const uint8_t *oid, size_t len)
{
    size_t m = der_size(d);
    der_oid(d, oid, len);
    der_wrap(d, m, SEQ);
}

/* Beginn eines Attributs: type OID + SET { value }, Aufrufer schreibt value davor. */
static void finish_attr(der_t *d, size_t mark, const uint8_t *oid, size_t oid_len)
{
    der_wrap(d, mark, SET);
    der_oid(d, oid, oid_len);
    der_wrap(d, mark, SEQ);
}

static esp_err_t format_time(time_t t, char *buf, size_t *len, uint8_t *tag)
{
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    int y = tm.tm_year + 1900;
    if (y < 1950 || y > 9999) { /* UTCTime/GeneralizedTime: 4-stelliges Jahr */
        return ESP_ERR_INVALID_ARG;
    }
    int n;
    if (y < 2050) { /* UTCTime YYMMDDHHMMSSZ */
        n = snprintf(buf, 20, "%02d%02d%02d%02d%02d%02dZ", y % 100, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        *tag = MBEDTLS_ASN1_UTC_TIME;
    } else { /* GeneralizedTime */
        n = snprintf(buf, 20, "%04d%02d%02d%02d%02d%02dZ", y, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        *tag = MBEDTLS_ASN1_GENERALIZED_TIME;
    }
    if (n < 0 || n >= 20) { /* abgeschnitten */
        return ESP_ERR_INVALID_ARG;
    }
    *len = (size_t)n;
    return ESP_OK;
}

esp_err_t cades_build(const cades_params_t *p, uint8_t *out, size_t out_size, size_t *out_len)
{
    if (!p || !p->sign || !out || !out_len || !p->dev_cert || !p->ca_certs ||
        p->ca_count == 0 || p->ca_count + 1 > DER_SET_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = ESP_ERR_NO_MEM;
    const size_t abs = CONFIG_ASICS_ATTRS_BUF_SIZE;
    uint8_t *scratch = malloc(2 * abs);
    mbedtls_x509_crt *own = p->dev_crt ? NULL : calloc(1, sizeof(*own)); /* nur ohne vorgeparstes Zertifikat */
    if (!scratch || (!p->dev_crt && !own)) {
        goto done;
    }
    const mbedtls_x509_crt *crt = p->dev_crt;
    if (!crt) {
        mbedtls_x509_crt_init(own);
        if (mbedtls_x509_crt_parse_der(own, p->dev_cert, p->dev_cert_len) != 0 || own->next != NULL) {
            err = ESP_ERR_INVALID_ARG;
            goto done;
        }
        crt = own;
    }

    /* ---- Signed Attributes: Einzelattribute in Bereich 1 ---- */
    der_t a;
    der_init(&a, scratch, abs);
    der_item_t items[4];

    /* content-type = id-data */
    size_t cur = der_size(&a); /* Beginn des jeweiligen Attributs */
    OID(&a, ASN1_OID_DATA);
    finish_attr(&a, cur, ASN1_OID_CONTENT_TYPE, sizeof(ASN1_OID_CONTENT_TYPE));
    items[0] = (der_item_t){a.p, der_size(&a) - cur};

    /* message-digest */
    cur = der_size(&a);
    der_octet_string(&a, p->payload_digest, ASICS_DIGEST_LEN);
    finish_attr(&a, cur, ASN1_OID_MSG_DIGEST, sizeof(ASN1_OID_MSG_DIGEST));
    items[1] = (der_item_t){a.p, der_size(&a) - cur};

    /* signing-time */
    char tbuf[20];
    size_t tlen;
    uint8_t ttag;
    err = format_time(p->signing_time, tbuf, &tlen, &ttag);
    if (err != ESP_OK) {
        goto done;
    }
    err = ESP_ERR_NO_MEM; /* ab hier: Fehler = Pufferueberlauf */
    cur = der_size(&a);
    der_string(&a, ttag, tbuf, tlen);
    finish_attr(&a, cur, ASN1_OID_SIGNING_TIME, sizeof(ASN1_OID_SIGNING_TIME));
    items[2] = (der_item_t){a.p, der_size(&a) - cur};

    /* signing-certificate-v2: ESSCertIDv2 (SHA-256 = DEFAULT, daher ohne hashAlgorithm) */
    uint8_t cert_hash[32];
    mbedtls_sha256(p->dev_cert, p->dev_cert_len, cert_hash, 0);
    cur = der_size(&a);
    {
        der_int_raw(&a, crt->serial.p, crt->serial.len);
        size_t m_gn = der_size(&a);
        der_raw(&a, crt->issuer_raw.p, crt->issuer_raw.len);
        der_wrap(&a, m_gn, 0xA4);        /* [4] directoryName */
        der_wrap(&a, m_gn, SEQ);         /* GeneralNames */
        der_wrap(&a, cur, SEQ);          /* IssuerSerial */
        der_octet_string(&a, cert_hash, sizeof(cert_hash)); /* certHash */
        der_wrap(&a, cur, SEQ);          /* ESSCertIDv2 */
        der_wrap(&a, cur, SEQ);          /* certs SEQUENCE OF */
        der_wrap(&a, cur, SEQ);          /* SigningCertificateV2 */
    }
    finish_attr(&a, cur, ASN1_OID_SIGNING_CERT_V2, sizeof(ASN1_OID_SIGNING_CERT_V2));
    items[3] = (der_item_t){a.p, der_size(&a) - cur};
    if (a.err) {
        goto done;
    }

    /* ---- SET OF sortiert in Bereich 2 (Tag 0x31 zum Hashen) ---- */
    der_t s;
    der_init(&s, scratch + abs, abs);
    der_set_of_sorted(&s, items, 4, SET);
    if (s.err) {
        goto done;
    }
    uint8_t digest[32];
    mbedtls_sha256(der_data(&s), der_size(&s), digest, 0);

    uint8_t sig[ASICS_SIG_MAX_LEN];
    size_t sig_len = 0;
    err = p->sign(digest, sig, sizeof(sig), &sig_len, p->sign_ctx);
    if (err != ESP_OK) {
        goto done;
    }
    err = ESP_ERR_NO_MEM;

    /* ---- Gesamtstruktur rueckwaerts ---- */
    der_t d;
    der_init(&d, out, out_size);
    size_t m_all = der_size(&d); /* Beginn von ContentInfo/[0]/SignedData */

    size_t m_si = der_size(&d);
    if (p->unsigned_attrs) {
        size_t m_ua = der_size(&d);
        esp_err_t herr = p->unsigned_attrs(&d, sig, sig_len, p->unsigned_ctx);
        if (herr != ESP_OK) {
            err = herr;
            goto done;
        }
        if (der_size(&d) > m_ua) { /* unsignedAttrs ist SET SIZE(1..MAX): bei leerem Hook weglassen */
            der_wrap(&d, m_ua, 0xA1);
        }
    }
    der_octet_string(&d, sig, sig_len);
    write_alg(&d, ASN1_OID_ECDSA_SHA256, sizeof(ASN1_OID_ECDSA_SHA256));
    der_raw(&d, der_data(&s), der_size(&s));
    if (!d.err) {
        d.p[0] = 0xA0; /* [0] IMPLICIT statt SET (Hash wurde mit 0x31 gebildet) */
    }
    write_alg(&d, ASN1_OID_SHA256, sizeof(ASN1_OID_SHA256));
    {   /* IssuerAndSerialNumber */
        size_t m_is = der_size(&d);
        der_int_raw(&d, crt->serial.p, crt->serial.len);
        der_raw(&d, crt->issuer_raw.p, crt->issuer_raw.len);
        /* Reihenfolge: issuer VOR serial -> beim Rueckwaertsschreiben serial zuerst: ok */
        der_wrap(&d, m_is, SEQ);
    }
    der_int(&d, 1);
    der_wrap(&d, m_si, SEQ);  /* SignerInfo */
    der_wrap(&d, m_si, SET);  /* signerInfos */

    {   /* certificates [0] IMPLICIT SET OF, DER-sortiert */
        der_item_t certs[DER_SET_MAX] = {{p->dev_cert, p->dev_cert_len}};
        for (size_t i = 0; i < p->ca_count; i++) {
            certs[i + 1] = (der_item_t){p->ca_certs[i].der, p->ca_certs[i].len};
        }
        der_set_of_sorted(&d, certs, p->ca_count + 1, 0xA0);
    }
    {   /* encapContentInfo: id-data ohne eContent (detached) */
        size_t m_e = der_size(&d);
        OID(&d, ASN1_OID_DATA);
        der_wrap(&d, m_e, SEQ);
    }
    {   /* digestAlgorithms */
        size_t m_a = der_size(&d);
        write_alg(&d, ASN1_OID_SHA256, sizeof(ASN1_OID_SHA256));
        der_wrap(&d, m_a, SET);
    }
    der_int(&d, 1);
    der_wrap(&d, m_all, SEQ);  /* SignedData */
    der_wrap(&d, m_all, 0xA0); /* [0] EXPLICIT */
    OID(&d, ASN1_OID_SIGNED_DATA);
    der_wrap(&d, m_all, SEQ);  /* ContentInfo */

    if (d.err) {
        ESP_LOGE(TAG, "CMS-Puffer zu klein (%u Byte)", (unsigned)out_size);
        goto done;
    }
    *out_len = der_size(&d);
    memmove(out, der_data(&d), *out_len);
    err = ESP_OK;

done:
    if (own) {
        mbedtls_x509_crt_free(own);
        free(own);
    }
    free(scratch);
    return err;
}
