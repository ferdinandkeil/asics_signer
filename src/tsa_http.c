/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* TSA-Transport (Zielsystem): HTTP-POST mit esp_http_client (RFC 3161 ueber HTTP). */
#include <string.h>
#include "tsa_transport.h"
#include "asics_signer.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "sdkconfig.h"

#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif

static const char *TAG = "asics_tsa_http";

esp_err_t asics_tsa_transport(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size, size_t *resp_len)
{
    if (CONFIG_ASICS_TSA_URL[0] == '\0') {
        ESP_LOGE(TAG, "keine TSA-URL konfiguriert (CONFIG_ASICS_TSA_URL)");
        return ASICS_ERR_TSA_UNAVAILABLE;
    }
    esp_http_client_config_t cfg = {
        .url = CONFIG_ASICS_TSA_URL,
        .method = HTTP_METHOD_POST,
        .timeout_ms = CONFIG_ASICS_TSA_TIMEOUT_MS,
        .disable_auto_redirect = true, /* eine TSA antwortet direkt; keine Umleitungen verfolgen */
    };
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    if (strncmp(CONFIG_ASICS_TSA_URL, "https://", 8) == 0) {
        cfg.crt_bundle_attach = esp_crt_bundle_attach; /* HTTPS-Serverzertifikat gegen das Bundle */
    }
#endif
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) {
        return ASICS_ERR_TSA_UNAVAILABLE;
    }
    esp_err_t err = ASICS_ERR_TSA_UNAVAILABLE;
    esp_http_client_set_header(c, "Content-Type", "application/timestamp-query");
    esp_http_client_set_header(c, "Accept", "application/timestamp-reply");
    if (esp_http_client_open(c, (int)req_len) != ESP_OK) {
        ESP_LOGE(TAG, "Verbindung zur TSA fehlgeschlagen");
        goto out;
    }
    if (esp_http_client_write(c, (const char *)req, (int)req_len) != (int)req_len) {
        ESP_LOGE(TAG, "Senden der Anfrage fehlgeschlagen");
        goto out_close;
    }
    if (esp_http_client_fetch_headers(c) < 0) {
        ESP_LOGE(TAG, "Antwortheader der TSA nicht lesbar");
        goto out_close;
    }
    int status = esp_http_client_get_status_code(c);
    if (status != 200) {
        ESP_LOGE(TAG, "TSA antwortet mit HTTP %d", status);
        goto out_close;
    }
    size_t total = 0;
    for (;;) {
        if (total == resp_size) { /* Puffer voll: kommt noch mehr, ist die Antwort zu gross */
            char extra;
            int n = esp_http_client_read(c, &extra, 1);
            if (n < 0) {
                goto out_close;
            }
            err = n == 0 ? ESP_OK : ESP_ERR_NO_MEM;
            break;
        }
        int n = esp_http_client_read(c, (char *)resp + total, (int)(resp_size - total));
        if (n < 0) {
            ESP_LOGE(TAG, "Lesen der TSA-Antwort fehlgeschlagen");
            goto out_close;
        }
        if (n == 0) {
            err = ESP_OK;
            break;
        }
        total += (size_t)n;
    }
    if (err == ESP_OK) {
        *resp_len = total;
    }
out_close:
    esp_http_client_close(c);
out:
    esp_http_client_cleanup(c);
    return err;
}
