/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Host-Transport: Test-TSA ueber das openssl-Kommandozeilenwerkzeug. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tsa_host.h"
#include "asics_signer.h"
#include "esp_log.h"

static const char *TAG = "asics_tsa_host";
static asics_tsa_host_hook_t s_hook;
static void *s_hook_ctx;
static char s_section[32] = "tsa_good";

void asics_tsa_host_set_hook(asics_tsa_host_hook_t hook, void *ctx)
{
    s_hook = hook;
    s_hook_ctx = ctx;
}

void asics_tsa_host_set_section(const char *section)
{
    snprintf(s_section, sizeof(s_section), "%s", section ? section : "tsa_good");
}

esp_err_t asics_tsa_host_openssl(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size, size_t *resp_len)
{
    const char *pki = getenv("ASICS_TEST_PKI");
    if (!pki) {
        ESP_LOGE(TAG, "ASICS_TEST_PKI nicht gesetzt");
        return ASICS_ERR_TSA_UNAVAILABLE;
    }
    char dir[] = "/tmp/asics_tsa_XXXXXX";
    if (!mkdtemp(dir)) {
        return ASICS_ERR_TSA_UNAVAILABLE;
    }
    char qpath[256], rpath[256], cmd[1024];
    snprintf(qpath, sizeof(qpath), "%s/req.tsq", dir);
    snprintf(rpath, sizeof(rpath), "%s/resp.tsr", dir);
    esp_err_t err = ASICS_ERR_TSA_UNAVAILABLE;
    FILE *f = fopen(qpath, "wb");
    if (f) {
        fwrite(req, 1, req_len, f);
        fclose(f);
        snprintf(cmd, sizeof(cmd), "openssl ts -reply -config '%s/tsa.cnf' -section %s -queryfile '%s' -out '%s' 2>/dev/null",
                 pki, s_section, qpath, rpath);
        if (system(cmd) == 0 && (f = fopen(rpath, "rb")) != NULL) {
            size_t n = fread(resp, 1, resp_size, f);
            int more = fgetc(f);
            fclose(f);
            if (more != EOF) {
                err = ESP_ERR_NO_MEM;
            } else {
                *resp_len = n;
                err = ESP_OK;
            }
        }
    }
    unlink(qpath);
    unlink(rpath);
    rmdir(dir);
    return err;
}

esp_err_t asics_tsa_transport(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size, size_t *resp_len)
{
    if (s_hook) {
        return s_hook(req, req_len, resp, resp_size, resp_len, s_hook_ctx);
    }
    return asics_tsa_host_openssl(req, req_len, resp, resp_size, resp_len);
}
