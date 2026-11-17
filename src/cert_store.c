/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>
#include "cert_store.h"
#include "cades_builder.h"
#include "tsa.h"
#include "asics_signer.h"
#include "kv_store.h"
#include "backend/key_backend.h"
#include "esp_log.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "sdkconfig.h"

static const char *TAG = "asics_cert";
#define CERTS_KEY "certs"

static int tm_cmp(const mbedtls_x509_time *a, const struct tm *b)
{
    int av[6] = {a->year, a->mon, a->day, a->hour, a->min, a->sec};
    int bv[6] = {b->tm_year + 1900, b->tm_mon + 1, b->tm_mday, b->tm_hour, b->tm_min, b->tm_sec};
    for (int i = 0; i < 6; i++) {
        if (av[i] != bv[i]) {
            return av[i] < bv[i] ? -1 : 1;
        }
    }
    return 0;
}

static bool valid_at(const mbedtls_x509_crt *c, time_t now)
{
    struct tm tm;
    gmtime_r(&now, &tm);
    return tm_cmp(&c->valid_from, &tm) <= 0 && tm_cmp(&c->valid_to, &tm) >= 0;
}

static esp_err_t parse_one(mbedtls_x509_crt *c, const uint8_t *der, size_t len)
{
    mbedtls_x509_crt_init(c);
    if (len == 0 || len > CONFIG_ASICS_CERT_MAX_LEN ||
        mbedtls_x509_crt_parse_der(c, der, len) != 0 || c->next != NULL) {
        return ASICS_ERR_CERT_PARSE;
    }
    return ESP_OK;
}

/* Selbstsigniert (Issuer == Subject)? */
static bool self_issued(const mbedtls_x509_crt *c)
{
    return c->issuer_raw.len == c->subject_raw.len &&
           memcmp(c->issuer_raw.p, c->subject_raw.p, c->issuer_raw.len) == 0;
}

/* child von parent signiert (parent als einziger Vertrauensanker); Zeit-Flags ignoriert */
static bool signed_by(mbedtls_x509_crt *child, mbedtls_x509_crt *parent)
{
    uint32_t flags = 0;
    int rc = mbedtls_x509_crt_verify(child, parent, NULL, NULL, &flags, NULL, NULL);
    flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    if ((rc != 0 && rc != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) || flags != 0) {
        ESP_LOGE(TAG, "Kettenpruefung fehlgeschlagen (rc=-0x%04x flags=0x%x)", -rc, (unsigned)flags);
        return false;
    }
    return true;
}

/* Platzhalter-Signer: maximale DER-ECDSA-Signaturlaenge (72 Byte) */
static esp_err_t probe_sign(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len, void *ctx)
{
    (void)digest; (void)ctx;
    static const uint8_t r[35] = {0x02, 0x21, 0x00, 0x80};
    if (sig_size < 72) {
        return ESP_ERR_NO_MEM;
    }
    size_t o = 0;
    sig[o++] = 0x30;
    sig[o++] = 70;
    for (int i = 0; i < 2; i++) {
        memcpy(sig + o, r, sizeof(r)); /* Rest ist Nullen: Inhalt egal, nur die Laenge zaehlt */
        o += sizeof(r);
    }
    *sig_len = o;
    return ESP_OK;
}

/* Probe-Hook: Zeitstempel-Token maximaler Groesse (CONFIG_ASICS_TSA_MAX_RESP) als unsigned attribute */
static esp_err_t probe_tsa_attr(der_t *d, const uint8_t *sig, size_t sig_len, void *ctx)
{
    (void)sig; (void)sig_len; (void)ctx;
    static const uint8_t oid[11] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E};
    static const uint8_t zeros[64] = {0};
    size_t m = der_size(d);
    size_t n = CONFIG_ASICS_TSA_MAX_RESP;
    while (n > 0 && !d->err) {
        size_t c = n > sizeof(zeros) ? sizeof(zeros) : n;
        der_raw(d, zeros, c);
        n -= c;
    }
    der_wrap(d, m, 0x31);
    der_oid(d, oid, sizeof(oid));
    der_wrap(d, m, 0x30);
    return ESP_OK;
}

/* Worst-Case-CMS (laengste Signatur, GeneralizedTime) mit den echten Puffergroessen bauen */
static esp_err_t probe_cms(const uint8_t *dev, size_t dev_len, const asics_der_t *chain, size_t chain_count)
{
    uint8_t *cms = malloc(CONFIG_ASICS_CMS_BUF_SIZE);
    if (!cms) {
        return ESP_ERR_NO_MEM;
    }
    cades_params_t p = {
        .signing_time = (time_t)4000000000LL, /* 2096: GeneralizedTime-Pfad, im ZIP-Bereich bis 2107 */
        .dev_cert = dev, .dev_cert_len = dev_len,
        .ca_certs = chain, .ca_count = chain_count,
        .sign = probe_sign,
    };
    if (tsa_configured()) { /* TSA-Betrieb moeglich: Platz fuer einen Token maximaler Groesse vorhalten */
        p.unsigned_attrs = probe_tsa_attr;
    }
    size_t n = 0;
    esp_err_t err = cades_build(&p, cms, CONFIG_ASICS_CMS_BUF_SIZE, &n);
    free(cms);
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "CMS passt nicht in CONFIG_ASICS_CMS_BUF_SIZE/CONFIG_ASICS_ATTRS_BUF_SIZE "
                      "(Kette zu gross oder Issuer-DN zu lang)");
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Probe-Build fehlgeschlagen: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t asics_cert_store_import(const uint8_t *dev, size_t dev_len,
                                  const asics_der_t *chain, size_t chain_count,
                                  bool check_time, time_t now)
{
    if (!dev || !chain || chain_count == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (chain_count + 1 > CONFIG_ASICS_MAX_CHAIN) {
        ESP_LOGE(TAG, "Zu viele Zertifikate (%u > %d)", (unsigned)(chain_count + 1), CONFIG_ASICS_MAX_CHAIN);
        return ESP_ERR_INVALID_SIZE;
    }
    size_t total = dev_len;
    for (size_t i = 0; i < chain_count; i++) {
        total += chain[i].len;
    }
    if (total > CONFIG_ASICS_CMS_BUF_SIZE) { /* Untergrenze; exakte Pruefung per Probe-Build unten */
        ESP_LOGE(TAG, "Kette (%u Byte) passt nicht in CONFIG_ASICS_CMS_BUF_SIZE", (unsigned)total);
        return ESP_ERR_NO_MEM;
    }

    size_t cnt = chain_count + 1;
    esp_err_t err;
    mbedtls_x509_crt *c = calloc(cnt, sizeof(*c)); /* c[0] = Geraet, c[1..] = Kette */
    size_t hdr = 1 + 2 * cnt;
    uint8_t *blob = malloc(hdr + total);
    if (!c || !blob) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    for (size_t i = 0; i < cnt; i++) {
        mbedtls_x509_crt_init(&c[i]);
    }
    if ((err = parse_one(&c[0], dev, dev_len)) != ESP_OK) {
        goto done;
    }
    for (size_t i = 0; i < chain_count; i++) {
        if ((err = parse_one(&c[i + 1], chain[i].der, chain[i].len)) != ESP_OK) {
            goto done;
        }
    }

    /* 1. Public Key == Geraeteschluessel */
    uint8_t key_pub[65];
    err = asics_key_get_public(key_pub);
    if (err != ESP_OK) {
        goto done;
    }
    if (mbedtls_pk_get_type(&c[0].pk) != MBEDTLS_PK_ECKEY || mbedtls_pk_get_bitlen(&c[0].pk) != 256) {
        err = ASICS_ERR_CERT_KEY_MISMATCH;
        goto done;
    }
    {
        uint8_t cert_pub[65];
        size_t olen = 0;
        mbedtls_ecp_keypair *kp = mbedtls_pk_ec(c[0].pk);
        if (mbedtls_ecp_write_public_key(kp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, cert_pub, sizeof(cert_pub)) != 0 ||
            olen != 65 || memcmp(cert_pub, key_pub, 65) != 0) {
            err = ASICS_ERR_CERT_KEY_MISMATCH;
            goto done;
        }
    }

    /* 2. Kette: c[k] von c[k+1] signiert; alle CAs mit CA-Flag */
    err = ASICS_ERR_CERT_CHAIN;
    for (size_t k = 1; k < cnt; k++) {
        if (mbedtls_x509_crt_get_ca_istrue(&c[k]) != 1) {
            ESP_LOGE(TAG, "Kettenglied %u hat kein CA-Flag", (unsigned)k);
            goto done;
        }
    }
    for (size_t k = 0; k + 1 < cnt; k++) {
        if (!signed_by(&c[k], &c[k + 1])) {
            ESP_LOGE(TAG, "Zertifikat %u nicht vom Nachfolger signiert (Reihenfolge/fehlendes Glied?)", (unsigned)k);
            goto done;
        }
    }
    if (self_issued(&c[cnt - 1]) && !signed_by(&c[cnt - 1], &c[cnt - 1])) {
        goto done; /* Root: Selbstsignatur ungueltig */
    }

    /* 3. Gueltigkeit (nur mit gueltiger Uhr) */
    if (check_time) {
        for (size_t k = 0; k < cnt; k++) {
            if (!valid_at(&c[k], now)) {
                ESP_LOGE(TAG, "Zertifikat %u ausserhalb des Gueltigkeitszeitraums", (unsigned)k);
                err = ASICS_ERR_CERT_VALIDITY;
                goto done;
            }
        }
    } else {
        ESP_LOGW(TAG, "Uhr ungueltig: Zeitpruefung beim Import uebersprungen");
    }

    /* 4. Probe-Build: passt das CMS (inkl. Issuer-DN/Serial in signing-certificate-v2 und sid)
     *    in CMS- und Attribut-Puffer? Sonst scheiterte spaeter jedes asics_sign(). */
    err = probe_cms(dev, dev_len, chain, chain_count);
    if (err != ESP_OK) {
        goto done;
    }

    /* Blob: n_ca(u8) | len[0..n_ca] (u16 LE) | Zertifikate */
    blob[0] = (uint8_t)chain_count;
    uint8_t *lp = blob + 1, *dp = blob + hdr;
    lp[0] = dev_len & 0xff; lp[1] = dev_len >> 8; lp += 2;
    memcpy(dp, dev, dev_len); dp += dev_len;
    for (size_t i = 0; i < chain_count; i++) {
        lp[0] = chain[i].len & 0xff; lp[1] = chain[i].len >> 8; lp += 2;
        memcpy(dp, chain[i].der, chain[i].len); dp += chain[i].len;
    }
    err = asics_kv_set(CERTS_KEY, blob, hdr + total, true);
done:
    if (c) {
        for (size_t i = 0; i < cnt; i++) mbedtls_x509_crt_free(&c[i]);
        free(c);
    }
    free(blob);
    return err;
}

esp_err_t asics_cert_store_load(uint8_t *buf, size_t buf_size, size_t *count,
                                asics_der_t refs[CONFIG_ASICS_MAX_CHAIN])
{
    size_t total = buf_size;
    esp_err_t err = asics_kv_get(CERTS_KEY, buf, &total);
    if (err == ESP_ERR_INVALID_SIZE) {
        return ESP_ERR_INVALID_STATE; /* groesser als konfiguriert */
    }
    if (err != ESP_OK) {
        return err;
    }
    size_t n_ca = total ? buf[0] : 0;
    size_t cnt = n_ca + 1;
    if (n_ca == 0 || cnt > CONFIG_ASICS_MAX_CHAIN || total < 1 + 2 * cnt) {
        return ESP_ERR_INVALID_STATE;
    }
    size_t off = 1 + 2 * cnt;
    for (size_t i = 0; i < cnt; i++) {
        size_t l = buf[1 + 2 * i] | (buf[2 + 2 * i] << 8);
        if (l == 0 || off + l > total) {
            return ESP_ERR_INVALID_STATE;
        }
        refs[i].der = buf + off;
        refs[i].len = l;
        off += l;
    }
    if (off != total) {
        return ESP_ERR_INVALID_STATE;
    }
    *count = cnt;
    return ESP_OK;
}

bool asics_cert_store_present(void)
{
    size_t len = 0;
    return asics_kv_get(CERTS_KEY, NULL, &len) == ESP_OK && len > 3;
}

esp_err_t asics_cert_check_validity_crt(const mbedtls_x509_crt *crt, time_t now)
{
    if (!valid_at(crt, now)) {
        ESP_LOGE(TAG, "Zertifikat zum angegebenen Zeitpunkt nicht gueltig");
        return ASICS_ERR_SIGNER_CERT_VALIDITY;
    }
    return ESP_OK;
}

esp_err_t asics_cert_check_validity(const uint8_t *der, size_t len, time_t now)
{
    mbedtls_x509_crt c;
    esp_err_t err = parse_one(&c, der, len);
    if (err == ESP_OK) {
        err = asics_cert_check_validity_crt(&c, now);
    }
    mbedtls_x509_crt_free(&c);
    return err;
}
