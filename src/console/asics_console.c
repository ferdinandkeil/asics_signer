/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * UART-Konsole: `asics status | csr | import`.
 * Es gibt keinen Befehl zum Setzen/Ersetzen des Schluessels.
 * Empfehlung: REPL-Task-Stack >= 6144 Byte.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "asics_provision.h"
#include "pem_util.h"
#include "time_source.h"
#include "esp_console.h"
#include "esp_err.h"
#include "sdkconfig.h"

#define PEM_BUF (((CONFIG_ASICS_CERT_MAX_LEN + 2) / 3) * 4 + 256)

static int cmd_status(void)
{
    static const char *names[] = {"NO_KEY", "KEY_NO_CERT", "PROVISIONED"};
    asics_state_t s = asics_signer_get_state();
    printf("state: %s\n", names[s]);
    uint8_t pub[65];
    if (asics_provision_get_public_key(pub) == ESP_OK) {
        printf("pubkey: ");
        for (int i = 0; i < 65; i++) printf("%02x", pub[i]);
        printf("\n");
    }
    time_t now;
    printf("clock: %s (min %lld)\n", asics_time_get(&now) == ESP_OK ? "ok" : "BELOW MINIMUM",
           (long long)asics_time_min());
    return 0;
}

static int cmd_csr(void)
{
    char *pem = malloc(CONFIG_ASICS_CSR_BUF_SIZE * 2);
    if (!pem) {
        return 1;
    }
    size_t len;
    esp_err_t err = asics_provision_create_csr_pem(pem, CONFIG_ASICS_CSR_BUF_SIZE * 2, &len);
    if (err == ESP_OK) {
        fputs(pem, stdout);
    } else {
        printf("error: %s\n", esp_err_to_name(err));
    }
    free(pem);
    return err == ESP_OK ? 0 : 1;
}

typedef enum { BLK_OK, BLK_END, BLK_ABORT } blk_t;

/* Liest einen PEM-Block zeilenweise von stdin. "abort" bricht ab; "end" (nur wenn allow_end
 * und noch kein BEGIN gelesen) beendet die Kettenliste. */
static blk_t read_block(const char *prompt, char *buf, size_t cap, bool allow_end)
{
    asics_pem_reader_t r;
    asics_pem_reader_init(&r, buf, cap, "CERTIFICATE");
    printf("%s\n", prompt);
    char line[128];
    for (;;) {
        if (!fgets(line, sizeof(line), stdin)) {
            return BLK_ABORT;
        }
        /* Steuerwoerter nur ausserhalb eines PEM-Blocks (innerhalb sind es Base64-Daten) */
        if (asics_pem_reader_is_command(&r, line, "abort")) {
            return BLK_ABORT;
        }
        if (allow_end && asics_pem_reader_is_command(&r, line, "end")) {
            return BLK_END;
        }
        asics_pem_state_t st = asics_pem_reader_feed(&r, line);
        if (st == ASICS_PEM_DONE) {
            return BLK_OK;
        }
        if (st == ASICS_PEM_ERROR) {
            printf("error: PEM zu gross\n");
            return BLK_ABORT;
        }
    }
}

/* Konvention: zuerst das Geraetezertifikat, dann die CA-Kette (Issuing-CA zuerst, Root zuletzt),
 * Ende der Kette mit der Zeile "end". */
static int cmd_import(void)
{
    const size_t cmax = CONFIG_ASICS_CERT_MAX_LEN;
    char *pem = malloc(PEM_BUF);
    uint8_t *der = malloc(CONFIG_ASICS_MAX_CHAIN * cmax);
    asics_der_t chain[CONFIG_ASICS_MAX_CHAIN];
    size_t dev_len = 0, n = 0;
    int ret = 1;
    if (!pem || !der) {
        goto out;
    }
    if (read_block("Geraetezertifikat (PEM) einfuegen, 'abort' bricht ab:", pem, PEM_BUF, false) != BLK_OK ||
        asics_pem_decode("CERTIFICATE", pem, strlen(pem), der, cmax, &dev_len) != ESP_OK) {
        printf("error: Geraetezertifikat ungueltig/abgebrochen\n");
        goto out;
    }
    for (;;) {
        blk_t b = read_block("CA-Zertifikat (PEM; Issuing-CA zuerst, Root zuletzt) oder 'end':", pem, PEM_BUF, true);
        if (b == BLK_ABORT) {
            goto out;
        }
        if (b == BLK_END) {
            break;
        }
        if (n + 2 > CONFIG_ASICS_MAX_CHAIN) {
            printf("error: zu viele Zertifikate (max. %d inkl. Geraetezertifikat)\n", CONFIG_ASICS_MAX_CHAIN);
            goto out;
        }
        uint8_t *slot = der + (n + 1) * cmax;
        size_t l;
        if (asics_pem_decode("CERTIFICATE", pem, strlen(pem), slot, cmax, &l) != ESP_OK) {
            printf("error: CA-Zertifikat ungueltig\n");
            goto out;
        }
        chain[n].der = slot;
        chain[n].len = l;
        n++;
    }
    if (n == 0) {
        printf("error: keine CA-Zertifikate\n");
        goto out;
    }
    esp_err_t err = asics_provision_import_der(der, dev_len, chain, n);
    if (err == ESP_OK) {
        printf("import ok (%u Zertifikate)\n", (unsigned)(n + 1));
        ret = 0;
    } else {
        printf("error: import fehlgeschlagen (0x%x %s)\n", (unsigned)err, esp_err_to_name(err));
    }
out:
    free(pem);
    free(der);
    return ret;
}

static int cmd_asics(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "status") == 0) return cmd_status();
    if (argc >= 2 && strcmp(argv[1], "csr") == 0) return cmd_csr();
    if (argc >= 2 && strcmp(argv[1], "import") == 0) return cmd_import();
    printf("usage: asics status | csr | import\n");
    return 1;
}

esp_err_t asics_console_register(void)
{
    const esp_console_cmd_t cmd = {
        .command = "asics",
        .help = "ASiC-S Provisionierung: status | csr | import",
        .hint = NULL,
        .func = &cmd_asics,
    };
    return esp_console_cmd_register(&cmd);
}
