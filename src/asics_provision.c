/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asics_provision.h"
#include "cert_store.h"
#include "csr_builder.h"
#include "pem_util.h"
#include "time_source.h"
#include "backend/key_backend.h"
#include "esp_log.h"
#include "sdkconfig.h"

#if CONFIG_IDF_TARGET_LINUX
#define HAVE_REAL_MAC 0
#else
#define HAVE_REAL_MAC 1
#include "esp_mac.h"
#endif

static const char *TAG = "asics_prov";
static char s_serial[65];

esp_err_t asics_provision_set_serial(const char *serial)
{
    if (!serial || !serial[0]) {
        s_serial[0] = 0;
        return ESP_OK;
    }
    if (strlen(serial) > 64) {
        return ESP_ERR_INVALID_ARG;
    }
    strcpy(s_serial, serial);
    return ESP_OK;
}

esp_err_t asics_provision_ensure_key(void)
{
    if (asics_key_has_key()) {
        return ESP_OK;
    }
    ESP_LOGI(TAG, "Erstinbetriebnahme: erzeuge Geraeteschluessel");
    return asics_key_generate();
}

esp_err_t asics_provision_get_public_key(uint8_t pub[65])
{
    return asics_key_get_public(pub);
}

static esp_err_t sign_cb(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len, void *ctx)
{
    (void)ctx;
    return asics_key_sign_digest(digest, sig, sig_size, sig_len);
}

esp_err_t asics_provision_create_csr(uint8_t *der, size_t size, size_t *len)
{
    if (!der || !len) {
        return ESP_ERR_INVALID_ARG;
    }
    csr_params_t p = {0};
    uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; /* Host-Test: fester Wert */
#if HAVE_REAL_MAC
    esp_err_t e = esp_efuse_mac_get_default(mac);
    if (e != ESP_OK) {
        return e;
    }
#endif
    char cn[13];
    snprintf(cn, sizeof(cn), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    p.cn = cn;
    p.serial = s_serial;
    p.org = CONFIG_ASICS_SUBJECT_ORG;
    p.country = CONFIG_ASICS_SUBJECT_COUNTRY;
    p.sign = sign_cb;
    esp_err_t err = asics_key_get_public(p.pub);
    if (err != ESP_OK) {
        return err;
    }
    return csr_build(&p, der, size, len);
}

esp_err_t asics_provision_create_csr_pem(char *pem, size_t size, size_t *len)
{
    uint8_t der[CONFIG_ASICS_CSR_BUF_SIZE];
    size_t dl = 0;
    esp_err_t err = asics_provision_create_csr(der, sizeof(der), &dl);
    if (err != ESP_OK) {
        return err;
    }
    return asics_pem_encode("CERTIFICATE REQUEST", der, dl, pem, size, len);
}

esp_err_t asics_provision_import_der(const uint8_t *dev, size_t dev_len,
                                     const asics_der_t *chain, size_t chain_count)
{
    time_t now = 0;
    bool clock_ok = asics_time_get(&now) == ESP_OK;
    if (!clock_ok) {
        ESP_LOGW(TAG, "Keine gueltige Uhrzeit - Gueltigkeitspruefung entfaellt");
    }
    return asics_cert_store_import(dev, dev_len, chain, chain_count, clock_ok, now);
}

esp_err_t asics_provision_import_pem(const char *dev_pem, const char *chain_pem)
{
    if (!dev_pem || !chain_pem) {
        return ESP_ERR_INVALID_ARG;
    }
    const size_t cmax = CONFIG_ASICS_CERT_MAX_LEN;
    uint8_t *mem = malloc(CONFIG_ASICS_MAX_CHAIN * cmax);
    asics_der_t chain[CONFIG_ASICS_MAX_CHAIN];
    size_t dev_len = 0, n = 0;
    esp_err_t err = ESP_ERR_NO_MEM;
    if (!mem) {
        return err;
    }
    err = asics_pem_decode("CERTIFICATE", dev_pem, strlen(dev_pem), mem, cmax, &dev_len);
    if (err != ESP_OK) {
        err = ASICS_ERR_CERT_PARSE;
        goto out;
    }
    const char *pos = chain_pem, *end = chain_pem + strlen(chain_pem);
    for (;;) {
        /* mehr Bloecke als Platz: ein weiterer Block wird gelesen und fuehrt zu INVALID_SIZE */
        if (n + 1 >= CONFIG_ASICS_MAX_CHAIN) {
            uint8_t probe[8];
            size_t pl;
            esp_err_t e = asics_pem_decode_next("CERTIFICATE", &pos, end, probe, sizeof(probe), &pl);
            if (e != ESP_ERR_NOT_FOUND) {
                err = ESP_ERR_INVALID_SIZE; /* auch bei "zu klein"-Fehlern: Block vorhanden */
                goto out;
            }
            break;
        }
        uint8_t *slot = mem + (n + 1) * cmax;
        size_t l = 0;
        esp_err_t e = asics_pem_decode_next("CERTIFICATE", &pos, end, slot, cmax, &l);
        if (e == ESP_ERR_NOT_FOUND) {
            break;
        }
        if (e != ESP_OK) {
            err = ASICS_ERR_CERT_PARSE;
            goto out;
        }
        chain[n].der = slot;
        chain[n].len = l;
        n++;
    }
    if (n == 0) {
        err = ASICS_ERR_CERT_PARSE;
        goto out;
    }
    err = asics_provision_import_der(mem, dev_len, chain, n);
out:
    free(mem);
    return err;
}

#if CONFIG_IDF_TARGET_LINUX || !CONFIG_ASICS_ENABLE_CONSOLE
esp_err_t asics_console_register(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}
#endif
