/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Light-Backend: ECDSA-P-256-Schluessel im NVS.
 * Sicherheit setzt verschluesseltes NVS (nvs_keys, geschuetzt durch Flash Encryption)
 * und Secure Boot v2 voraus. Der ESP32 hat kein HMAC-Peripheral, daher gibt es
 * keine HMAC-basierte NVS-Schluesselableitung.
 *
 * Blob "key" (98 Byte, atomar): version(1)=0x01 || d(32) || Q(65, unkomprimiert)
 */
#include <string.h>
#include "sdkconfig.h"
#include "key_backend.h"

#if CONFIG_ASICS_KEY_BACKEND_NVS

#include "kv_store.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform_util.h"

#if !CONFIG_IDF_TARGET_LINUX
#include "esp_flash_encrypt.h"
#if CONFIG_ASICS_BOOTLOADER_RANDOM
#include "bootloader_random.h"
#endif
#endif

static const char *TAG = "asics_key";
#define KEY_NAME "key"
#define BLOB_LEN (1 + 32 + 65)
#define BLOB_VERSION 0x01

static int rng_cb(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

esp_err_t asics_key_init(void)
{
    return asics_kv_init();
}

bool asics_key_has_key(void)
{
    size_t len = 0;
    return asics_kv_get(KEY_NAME, NULL, &len) == ESP_OK && len == BLOB_LEN;
}

esp_err_t asics_key_generate(void)
{
    if (asics_key_has_key()) {
        return ESP_ERR_INVALID_STATE; /* vorhandenen Schluessel niemals ersetzen */
    }
#if !CONFIG_IDF_TARGET_LINUX
    if (!esp_flash_encryption_enabled()) {
#if CONFIG_ASICS_REQUIRE_FLASH_ENCRYPTION
        ESP_LOGE(TAG, "Flash Encryption nicht aktiv - Schluesselerzeugung verweigert");
        return ESP_ERR_INVALID_STATE;
#else
        ESP_LOGW(TAG, "Flash Encryption nicht aktiv - Schluessel liegt UNGESCHUETZT im NVS (nur Entwicklung!)");
#endif
    }
#endif

    uint8_t blob[BLOB_LEN];
    size_t olen = 0;
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    esp_err_t err = ESP_FAIL;

#if !CONFIG_IDF_TARGET_LINUX && CONFIG_ASICS_BOOTLOADER_RANDOM
    bootloader_random_enable(); /* echte Entropie auch ohne aktives RF */
#endif
    int rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, rng_cb, NULL);
#if !CONFIG_IDF_TARGET_LINUX && CONFIG_ASICS_BOOTLOADER_RANDOM
    bootloader_random_disable();
#endif
    if (rc != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_gen_key: -0x%04x", -rc);
        goto out;
    }
    blob[0] = BLOB_VERSION;
    if (mbedtls_ecp_write_key_ext(&kp, &olen, blob + 1, 32) != 0 || olen != 32 ||
        mbedtls_ecp_write_public_key(&kp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, blob + 33, 65) != 0 ||
        olen != 65 || mbedtls_ecp_check_pub_priv(&kp, &kp, rng_cb, NULL) != 0) {
        goto out;
    }
    err = asics_kv_set(KEY_NAME, blob, sizeof(blob), false);
out:
    mbedtls_platform_zeroize(blob, sizeof(blob));
    mbedtls_ecp_keypair_free(&kp);
    return err;
}

esp_err_t asics_key_get_public(uint8_t pub[65])
{
    uint8_t blob[BLOB_LEN];
    size_t len = sizeof(blob);
    esp_err_t err = asics_kv_get(KEY_NAME, blob, &len);
    if (err == ESP_OK && (len != BLOB_LEN || blob[0] != BLOB_VERSION)) {
        err = ESP_ERR_INVALID_STATE;
    }
    if (err == ESP_OK) {
        memcpy(pub, blob + 33, 65);
    }
    mbedtls_platform_zeroize(blob, sizeof(blob));
    return err;
}

esp_err_t asics_key_sign_digest(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len)
{
    uint8_t blob[BLOB_LEN];
    size_t len = sizeof(blob);
    esp_err_t err = asics_kv_get(KEY_NAME, blob, &len);
    if (err == ESP_OK && (len != BLOB_LEN || blob[0] != BLOB_VERSION)) {
        err = ESP_ERR_INVALID_STATE;
    }
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(blob, sizeof(blob));
        return err;
    }
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    err = ESP_FAIL;
    if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &kp, blob + 1, 32) == 0 &&
        mbedtls_ecdsa_write_signature(&kp, MBEDTLS_MD_SHA256, digest, 32, sig, sig_size, sig_len,
                                      rng_cb, NULL) == 0) {
        err = ESP_OK;
    }
    mbedtls_platform_zeroize(blob, sizeof(blob));
    mbedtls_ecp_keypair_free(&kp);
    return err;
}

#endif /* CONFIG_ASICS_KEY_BACKEND_NVS */
