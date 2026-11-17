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
#include "backend/key_backend.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"

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

    uint8_t *mem = malloc(ASICS_CERT_BLOB_MAX + CONFIG_ASICS_CMS_BUF_SIZE);
    if (!mem) {
        return ESP_ERR_NO_MEM;
    }
    uint8_t *blob = mem, *cms = mem + ASICS_CERT_BLOB_MAX;
    cades_params_t p = {.signing_time = now, .sign = hal_sign};
    asics_der_t refs[CONFIG_ASICS_MAX_CHAIN];
    size_t cnt = 0, cms_len = 0;

    err = asics_cert_store_load(blob, ASICS_CERT_BLOB_MAX, &cnt, refs);
    if (err != ESP_OK) {
        goto out;
    }
    err = asics_cert_check_validity(refs[0].der, refs[0].len, now);
    if (err != ESP_OK) {
        goto out; /* ASICS_ERR_SIGNER_CERT_VALIDITY: keine Signatur */
    }
    p.dev_cert = refs[0].der;
    p.dev_cert_len = refs[0].len;
    p.ca_certs = &refs[1];
    p.ca_count = cnt - 1;
    mbedtls_sha256(data ? data : (const uint8_t *)"", len, p.payload_digest, 0);
    err = cades_build(&p, cms, CONFIG_ASICS_CMS_BUF_SIZE, &cms_len);
    if (err != ESP_OK) {
        goto out;
    }
    err = asics_container_write(payload_name, data, len, cms, cms_len, now, write, ctx);
out:
    free(mem);
    return err;
}
