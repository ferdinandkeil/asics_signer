/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
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

#if defined(ASICS_TSA_CA_EMBEDDED)
extern const char asics_tsa_ca_pem_start[] asm("_binary_asics_tsa_ca_pem_start");
static const char *ca_pem(void) { return asics_tsa_ca_pem_start; }
#elif CONFIG_IDF_TARGET_LINUX
static const char *s_host_ca;
void asics_tsa_host_set_ca_pem(const char *pem) { s_host_ca = pem; }
static const char *ca_pem(void) { return s_host_ca; }
#else
static const char *ca_pem(void) { return NULL; }
#endif

bool tsa_configured(void)
{
    return CONFIG_ASICS_TSA_URL[0] != '\0';
}

/* Token holen und pruefen; token/token_len zeigen in resp. */
static esp_err_t fetch_token(tsa_hook_ctx_t *c, const uint8_t *sig, size_t sig_len,
                             const uint8_t **token, size_t *token_len)
{
    const char *pem = ca_pem();
    if (!pem || !pem[0]) {
        ESP_LOGE(TAG, "keine TSA-CA eingebettet (CONFIG_ASICS_TSA_CA_PEM)");
        return ASICS_ERR_TSA_UNAVAILABLE;
    }
    uint8_t ca[CONFIG_ASICS_CERT_MAX_LEN];
    size_t ca_len;
    if (asics_pem_decode("CERTIFICATE", pem, strlen(pem), ca, sizeof(ca), &ca_len) != ESP_OK) {
        ESP_LOGE(TAG, "eingebettete TSA-CA nicht lesbar");
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
        (err = tsa_verify_token(&t, ca, ca_len, gen_time)) != ESP_OK) {
        return err == ESP_ERR_NO_MEM ? ASICS_ERR_TSA_UNAVAILABLE : err;
    }
    *token = r.token;
    *token_len = r.token_len;
    c->gen_time = gen_time;
    return ESP_OK;
}

esp_err_t tsa_attr_hook(der_t *d, const uint8_t *sig, size_t sig_len, void *ctx)
{
    tsa_hook_ctx_t *c = ctx;
    const uint8_t *token = NULL;
    size_t token_len = 0;
    c->embedded = false;
    c->err = fetch_token(c, sig, sig_len, &token, &token_len);
    if (c->err != ESP_OK) {
        ESP_LOGW(TAG, "kein Zeitstempel: %s", esp_err_to_name(c->err));
        return c->mode == ASICS_TSA_REQUIRED ? c->err : ESP_OK; /* PREFERRED: nichts schreiben -> B-B */
    }
    /* Attribute { OID signature-time-stamp, SET { TimeStampToken } } */
    size_t m = der_size(d);
    der_raw(d, token, token_len);
    der_wrap(d, m, 0x31);
    der_oid(d, ASN1_OID_SIG_TIMESTAMP, sizeof(ASN1_OID_SIG_TIMESTAMP));
    der_wrap(d, m, 0x30);
    if (d->err) {
        c->err = ESP_ERR_NO_MEM;
        return ESP_ERR_NO_MEM; /* CMS-Puffer zu klein: auch bei PREFERRED ein harter Fehler (Konfiguration) */
    }
    c->embedded = true;
    return ESP_OK;
}
