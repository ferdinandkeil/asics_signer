/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Beispiel: CSV-Datensatz signieren und den ASiC-S-Container als Base64 ausgeben.
 *
 * Provisionierung ueber die UART-Konsole:
 *   asics status   - Zustand, Public Key, Uhr
 *   asics csr      - PKCS#10-CSR als PEM (zur Fertigungs-CA bringen)
 *   asics import   - Geraetezertifikat + CA als PEM einfuegen
 * Zusaetzlich in diesem Beispiel:
 *   settime <epoch>  - Uhr setzen (ohne RTC/NTP)
 *   sign             - Beispiel-CSV signieren (Ausgabe Base64)
 *
 * PRODUKTION: NVS mit nvs_flash_secure_init() und nvs_keys-Partition (Flash Encryption)
 * betreiben; hier fuer den Entwicklungsaufbau unverschluesselt.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "esp_console.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "mbedtls/base64.h"
#include "asics_signer.h"
#include "asics_provision.h"

static const char *TAG = "basic_sign";

/* Streaming-Senke: sammelt Container im RAM und gibt ihn danach als Base64 aus. */
typedef struct { uint8_t *buf; size_t len, cap; } sink_t;

static esp_err_t sink_write(const void *buf, size_t len, void *ctx)
{
    sink_t *s = ctx;
    if (s->len + len > s->cap) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(s->buf + s->len, buf, len);
    s->len += len;
    return ESP_OK;
}

static int cmd_sign(int argc, char **argv)
{
    static const char csv[] = "zeit;wert\n2026-01-15T12:00:00Z;42,5\n";
    sink_t s = {.cap = 8192};
    s.buf = malloc(s.cap);
    if (!s.buf) return 1;
    esp_err_t err = asics_sign("messung.csv", (const uint8_t *)csv, sizeof(csv) - 1, sink_write, &s);
    if (err == ESP_OK) {
        size_t o = 0;
        char *b64 = malloc(s.len * 2);
        if (b64 && mbedtls_base64_encode((unsigned char *)b64, s.len * 2, &o, s.buf, s.len) == 0) {
            printf("-----BEGIN ASICS-----\n%.*s\n-----END ASICS-----\n", (int)o, b64);
        }
        free(b64);
    } else {
        printf("sign: %s\n", esp_err_to_name(err));
    }
    free(s.buf);
    return err == ESP_OK ? 0 : 1;
}

static int cmd_settime(int argc, char **argv)
{
    if (argc < 2) return 1;
    struct timeval tv = {.tv_sec = (time_t)atoll(argv[1])};
    return settimeofday(&tv, NULL) == 0 ? 0 : 1;
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    /* Seriennummer fuer das CSR-Subject (kundenspezifisch) */
    asics_config_t cfg = {.device_serial = "DEMO-0001"};
    ESP_ERROR_CHECK(asics_signer_init(&cfg));
    ESP_LOGI(TAG, "Zustand: %d", (int)asics_signer_get_state());

    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t rc = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    rc.task_stack_size = 8192;
    rc.prompt = "asics> ";
    esp_console_dev_uart_config_t uc = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uc, &rc, &repl));
    ESP_ERROR_CHECK(asics_console_register());
    const esp_console_cmd_t c1 = {.command = "sign", .help = "Beispiel-CSV signieren", .func = &cmd_sign};
    const esp_console_cmd_t c2 = {.command = "settime", .help = "settime <epoch>", .func = &cmd_settime};
    ESP_ERROR_CHECK(esp_console_cmd_register(&c1));
    ESP_ERROR_CHECK(esp_console_cmd_register(&c2));
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
