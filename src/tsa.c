/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "mbedtls/x509_crt.h"
#include <string.h>
#include "tsa.h"
#include "pem_util.h"
#include "time_source.h"
#include "tsa_req.h"
#include "tsa_resp.h"
#include "tsa_transport.h"
#include "tsa_verify.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "sdkconfig.h"
#include "tsa_host.h"
#include "asn1_oids.h"

static const char *TAG = "asics_tsa";

/* id-aa-signatureTimeStampToken = 1.2.840.113549.1.9.16.2.14 */

/* TSA-CA: einmal (lazy) aus dem PEM auf dem Heap dekodiert und als geparstes Zertifikat gecacht. Die
 * Puffergroesse ergibt sich aus der PEM-Laenge (keine feste Obergrenze fuer Zertifikate). */
static mbedtls_x509_crt *s_ca;
static const char *s_ca_loaded_from;

#if defined(ASICS_TSA_CA_EMBEDDED)
extern const char asics_tsa_ca_pem_start[] asm("_binary_asics_tsa_ca_pem_start");
static const char *ca_pem(void) { return asics_tsa_ca_pem_start; }
#elif CONFIG_IDF_TARGET_LINUX
static const char *s_host_ca;
void asics_tsa_host_set_ca_pem(const char *pem)
{
    s_host_ca = pem;
    if (s_ca) {   /* Cache verwerfen */
        mbedtls_x509_crt_free(s_ca);
        free(s_ca);
        s_ca = NULL;
    }
    s_ca_loaded_from = NULL;
}
static const char *ca_pem(void) { return s_host_ca; }
#else
static const char *ca_pem(void) { return NULL; }
#endif

/* liefert die gecachte TSA-CA (nur gueltige, einzelne CA-Zertifikate werden gecacht) oder NULL */
static const mbedtls_x509_crt *ca_get(void)
{
    const char *pem = ca_pem();
    if (!pem || !pem[0]) {
        ESP_LOGE(TAG, "keine TSA-CA eingebettet (CONFIG_ASICS_TSA_CA_PEM)");
        return NULL;
    }
    if (s_ca && s_ca_loaded_from == pem) {
        return s_ca;
    }
    size_t pem_len = strlen(pem);
    uint8_t *der = malloc(pem_len / 4 * 3 + 8);   /* Base64 -> DER ist hoechstens 3/4 der PEM-Laenge */
    mbedtls_x509_crt *crt = calloc(1, sizeof(*crt));
    size_t der_len = 0;
    const mbedtls_x509_crt *ret = NULL;
    if (der && crt && asics_pem_decode("CERTIFICATE", pem, pem_len, der, pem_len / 4 * 3 + 8, &der_len) == ESP_OK) {
        mbedtls_x509_crt_init(crt);
        if (mbedtls_x509_crt_parse_der(crt, der, der_len) != 0 || crt->next != NULL) {
            ESP_LOGE(TAG, "eingebettete TSA-CA nicht parsebar (genau ein Zertifikat erwartet)");
        } else if (mbedtls_x509_crt_get_ca_istrue(crt) != 1) {
            ESP_LOGE(TAG, "eingebettete TSA-CA hat kein CA-Flag");
        } else {
            if (s_ca) {
                mbedtls_x509_crt_free(s_ca);
                free(s_ca);
            }
            s_ca = crt;
            s_ca_loaded_from = pem;
            crt = NULL;
            ret = s_ca;
        }
    } else {
        ESP_LOGE(TAG, "eingebettete TSA-CA nicht lesbar");
    }
    if (crt) {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }
    free(der);
    return ret;
}

bool tsa_configured(void)
{
    return CONFIG_ASICS_TSA_URL[0] != '\0';
}

/* Token holen und pruefen; token/token_len zeigen in resp. */
static esp_err_t fetch_token(tsa_hook_ctx_t *c, const uint8_t *sig, size_t sig_len,
                             const uint8_t **token, size_t *token_len)
{
    const mbedtls_x509_crt *ca = ca_get();
    if (!ca) {
        return ASICS_ERR_TSA_UNAVAILABLE;
    }

    uint8_t digest[32], nonce[ASICS_TSA_NONCE_LEN], req[160];
    size_t req_len;
    mbedtls_sha256(sig, sig_len, digest, 0);   /* messageImprint = SHA-256 ueber die Oktette des Signaturwerts */
    esp_fill_random(nonce, sizeof(nonce));
    esp_err_t err = asics_tsa_build_request(digest, nonce, CONFIG_ASICS_TSA_POLICY_OID, req, sizeof(req), &req_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TimeStampReq: %s (CONFIG_ASICS_TSA_POLICY_OID pruefen)", esp_err_to_name(err));
        return ASICS_ERR_TSA_INVALID;
    }
    size_t resp_len = 0;
    err = asics_tsa_transport(req, req_len, c->resp, CONFIG_ASICS_TSA_MAX_RESP, &resp_len);
    if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "TSA-Antwort groesser als CONFIG_ASICS_TSA_MAX_RESP");
        return ASICS_ERR_TSA_INVALID;
    }
    if (err != ESP_OK) {
        return (err == ASICS_ERR_TSA_UNAVAILABLE || err == ASICS_ERR_TSA_REJECTED || err == ASICS_ERR_TSA_INVALID)
                   ? err : ASICS_ERR_TSA_UNAVAILABLE;
    }
    tsa_resp_t r;
    tsa_token_t t;
    time_t gen_time;
    tsa_expect_t e = {.digest = digest, .nonce = nonce, .nonce_len = sizeof(nonce), .now = c->now,
                      .tolerance_s = CONFIG_ASICS_TSA_GENTIME_TOLERANCE_S,
                      .policy_oid = CONFIG_ASICS_TSA_POLICY_OID};
    if ((err = tsa_parse_response(c->resp, resp_len, &r)) != ESP_OK ||
        (err = tsa_parse_token(r.token, r.token_len, &t)) != ESP_OK ||
        (err = tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gen_time)) != ESP_OK ||
        (err = tsa_verify_token(&t, ca, gen_time)) != ESP_OK) {
        return err == ESP_ERR_NO_MEM ? ASICS_ERR_TSA_UNAVAILABLE : err;
    }
    *token = r.token;
    *token_len = r.token_len;
    c->gen_time = gen_time;
    return ESP_OK;
}

esp_err_t tsa_fetch(tsa_hook_ctx_t *c, const uint8_t *sig, size_t sig_len)
{
    c->embedded = false;
    c->token = NULL;
    c->token_len = 0;
    c->err = fetch_token(c, sig, sig_len, &c->token, &c->token_len);
    if (c->err != ESP_OK) {
        ESP_LOGW(TAG, "kein Zeitstempel: %s", esp_err_to_name(c->err));
    }
    return c->err;
}

esp_err_t tsa_embed_hook(der_t *d, const uint8_t *sig, size_t sig_len, void *ctx)
{
    (void)sig; (void)sig_len;
    tsa_hook_ctx_t *c = ctx;
    /* Attribute { OID signature-time-stamp, SET { TimeStampToken } } */
    size_t m = der_size(d);
    der_raw(d, c->token, c->token_len);
    der_wrap(d, m, 0x31);
    der_oid(d, ASN1_OID_SIG_TIMESTAMP, sizeof(ASN1_OID_SIG_TIMESTAMP));
    der_wrap(d, m, 0x30);
    if (d->err) {
        return ESP_ERR_NO_MEM; /* passt nicht in den CMS-Puffer */
    }
    c->embedded = true;
    return ESP_OK;
}
