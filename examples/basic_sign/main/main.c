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
 *   settime <epoch>  - Uhr setzen (ohne RTC/NTP; fuer Zeitstempel auf wenige Minuten genau)
 *   wifi <ssid> <passwort>          - WLAN-Station verbinden (nichts wird gespeichert, WIFI_STORAGE_RAM)
 *   tsa-mode off|preferred|required - Zeitstempel-Modus (CAdES-B-T) zur Laufzeit
 *   sign             - Beispiel-CSV signieren; gibt Niveau/TSA-Fehler/genTime und den Container (Base64) aus
 *
 * Zeitstempel: CONFIG_ASICS_TSA_URL und CONFIG_ASICS_TSA_CA_PEM (siehe README) setzen.
 *
 * PRODUKTION: NVS mit nvs_flash_secure_init() und nvs_keys-Partition (Flash Encryption)
 * betreiben; hier fuer den Entwicklungsaufbau unverschluesselt.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "esp_console.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
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
    sink_t s = {.cap = 12288};
    s.buf = malloc(s.cap);
    if (!s.buf) return 1;
    asics_sign_result_t res;
    esp_err_t err = asics_sign_ex("messung.csv", (const uint8_t *)csv, sizeof(csv) - 1, sink_write, &s, &res);
    if (err == ESP_OK) {
        printf("level: %s\n", res.level == ASICS_LEVEL_B_T ? "CAdES-B-T" : "CAdES-B-B");
        if (res.level == ASICS_LEVEL_B_T) {
            printf("tsa genTime: %lld\n", (long long)res.tsa_gen_time);
        } else if (res.tsa_err != ESP_OK) {
            printf("tsa_err: 0x%x (%s)\n", (unsigned)res.tsa_err, esp_err_to_name(res.tsa_err));
        }
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

static EventGroupHandle_t s_wifi_events;
#define WIFI_GOT_IP BIT0

static void wifi_event_cb(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_wifi_events, WIFI_GOT_IP);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_wifi_events, WIFI_GOT_IP);
    }
}

/* wifi <ssid> <passwort>: STA verbinden, Zugangsdaten nur im RAM */
static int cmd_wifi(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: wifi <ssid> [passwort]\n");
        return 1;
    }
    static bool inited;
    if (!inited) {
        s_wifi_events = xEventGroupCreate();
        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());
        esp_netif_create_default_wifi_sta();
        wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&wc));
        ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));    /* keine Zugangsdaten im Flash */
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_cb, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_cb, NULL));
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        inited = true;
    } else {
        esp_wifi_disconnect();
        esp_wifi_stop();
    }
    wifi_config_t c = {0};
    strlcpy((char *)c.sta.ssid, argv[1], sizeof(c.sta.ssid));
    if (argc > 2) {
        strlcpy((char *)c.sta.password, argv[2], sizeof(c.sta.password));
    }
    xEventGroupClearBits(s_wifi_events, WIFI_GOT_IP);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());
    EventBits_t b = xEventGroupWaitBits(s_wifi_events, WIFI_GOT_IP, pdFALSE, pdTRUE, pdMS_TO_TICKS(20000));
    printf(b & WIFI_GOT_IP ? "wifi: verbunden\n" : "wifi: keine Verbindung (Timeout)\n");
    return b & WIFI_GOT_IP ? 0 : 1;
}

static int cmd_tsa_mode(int argc, char **argv)
{
    static const char *names[] = {"off", "preferred", "required"};
    if (argc == 2) {
        for (int i = 0; i < 3; i++) {
            if (strcmp(argv[1], names[i]) == 0) {
                asics_set_tsa_mode((asics_tsa_mode_t)(i + 1));   /* 0 = DEFAULT */
            }
        }
    }
    printf("tsa-mode: %s\n", names[asics_get_tsa_mode() - 1]);
    return 0;
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
    asics_config_t cfg = {.device_serial = "DEMO-0001", .tsa_mode = ASICS_TSA_OFF};   /* Modus spaeter: tsa-mode */
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
    const esp_console_cmd_t c3 = {.command = "wifi", .help = "wifi <ssid> [passwort]", .func = &cmd_wifi};
    const esp_console_cmd_t c4 = {.command = "tsa-mode", .help = "tsa-mode [off|preferred|required]", .func = &cmd_tsa_mode};
    const esp_console_cmd_t c2 = {.command = "settime", .help = "settime <epoch>", .func = &cmd_settime};
    ESP_ERROR_CHECK(esp_console_cmd_register(&c1));
    ESP_ERROR_CHECK(esp_console_cmd_register(&c2));
    ESP_ERROR_CHECK(esp_console_cmd_register(&c3));
    ESP_ERROR_CHECK(esp_console_cmd_register(&c4));
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
