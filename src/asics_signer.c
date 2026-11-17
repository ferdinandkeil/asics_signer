/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "asics_signer.h"
#include "asics_provision.h"
#include "asics_container.h"
#include "cades_builder.h"
#include "cert_store.h"
#include "kv_store.h"
#include "time_source.h"
#include "zip_writer.h"
#include "backend/key_backend.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

static inline bool len_fits_u32(size_t n)
{
#if SIZE_MAX > 0xFFFFFFFFu
    return n <= 0xFFFFFFFFu;
#else
    (void)n;
    return true;
#endif
}

static const char *TAG = "asics";
static bool s_inited;

esp_err_t asics_signer_init(const asics_config_t *cfg)
{
    esp_err_t err = asics_key_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Backend-Init: %s", esp_err_to_name(err));
        return err;
    }
    s_inited = true;
    if (cfg && cfg->device_serial) {
        err = asics_provision_set_serial(cfg->device_serial);
        if (err != ESP_OK) {
            return err;
        }
    }
#if CONFIG_ASICS_AUTO_GENERATE_KEY
    err = asics_provision_ensure_key();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Schluesselerzeugung: %s", esp_err_to_name(err));
        return err;
    }
#endif
    return ESP_OK;
}

asics_state_t asics_signer_get_state(void)
{
    if (!s_inited || !asics_key_has_key()) {
        return ASICS_STATE_NO_KEY;
    }
    return asics_cert_store_present() ? ASICS_STATE_PROVISIONED : ASICS_STATE_KEY_NO_CERT;
}

static esp_err_t hal_sign(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len, void *ctx)
{
    (void)ctx;
    return asics_key_sign_digest(digest, sig, sig_size, sig_len);
}

esp_err_t asics_sign(const char *payload_name, const uint8_t *data, size_t len,
                     asics_write_cb_t write, void *ctx)
{
    if (!write || (!data && len) || !len_fits_u32(len) ||
        asics_container_check_name(payload_name) != ESP_OK) {
        return ESP_ERR_INVALID_ARG;
    }
    if (asics_signer_get_state() != ASICS_STATE_PROVISIONED) {
        return ESP_ERR_INVALID_STATE;
    }
    time_t now;
    esp_err_t err = asics_time_get(&now);
    if (err != ESP_OK) {
        return err; /* ESP_ERR_INVALID_STATE: Uhr unter Mindestzeit, keine Signatur */
    }
    uint16_t dos_t, dos_d;
    if (zip_dos_time(now, &dos_t, &dos_d) != ESP_OK) {
        /* Zeit ausserhalb des ZIP-DOS-Bereichs (1980..2107): im Container nicht darstellbar */
        ESP_LOGE(TAG, "Signierzeit ausserhalb 1980..2107 - keine Signatur");
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t *mem = malloc(ASICS_CERT_BLOB_MAX + CONFIG_ASICS_CMS_BUF_SIZE);
    mbedtls_x509_crt *dev_crt = calloc(1, sizeof(*dev_crt));
    if (!mem || !dev_crt) {
        free(mem);
        free(dev_crt);
        return ESP_ERR_NO_MEM;
    }
    mbedtls_x509_crt_init(dev_crt);
    uint8_t *blob = mem, *cms = mem + ASICS_CERT_BLOB_MAX;
    cades_params_t p = {.signing_time = now, .sign = hal_sign};
    asics_der_t refs[CONFIG_ASICS_MAX_CHAIN];
    size_t cnt = 0, cms_len = 0;

    err = asics_cert_store_load(blob, ASICS_CERT_BLOB_MAX, &cnt, refs);
    if (err != ESP_OK) {
        goto out;
    }
    /* Geraetezertifikat einmal parsen: Validitaetspruefung und cades_build nutzen dasselbe Ergebnis */
    if (mbedtls_x509_crt_parse_der(dev_crt, refs[0].der, refs[0].len) != 0 || dev_crt->next != NULL) {
        err = ASICS_ERR_CERT_PARSE;
        goto out;
    }
    for (size_t i = 0; i < cnt; i++) { /* Geraetezertifikat und alle CA-Zertifikate der Kette */
        err = i == 0 ? asics_cert_check_validity_crt(dev_crt, now)
                     : asics_cert_check_validity(refs[i].der, refs[i].len, now);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Zertifikat %u der Kette zum Signierzeitpunkt nicht gueltig - keine Signatur", (unsigned)i);
            goto out; /* ASICS_ERR_SIGNER_CERT_VALIDITY */
        }
    }
    p.dev_cert = refs[0].der;
    p.dev_cert_len = refs[0].len;
    p.dev_crt = dev_crt;
    p.ca_certs = &refs[1];
    p.ca_count = cnt - 1;
    mbedtls_sha256(data ? data : (const uint8_t *)"", len, p.payload_digest, 0);
    err = cades_build(&p, cms, CONFIG_ASICS_CMS_BUF_SIZE, &cms_len);
    if (err != ESP_OK) {
        goto out;
    }
    err = asics_container_write(payload_name, data, len, cms, cms_len, now, write, ctx);
out:
    mbedtls_x509_crt_free(dev_crt);
    free(dev_crt);
    free(mem);
    return err;
}
