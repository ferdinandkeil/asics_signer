/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Host-Transport: Test-TSA ueber das openssl-Kommandozeilenwerkzeug. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
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
    /* nur [A-Za-z0-9_]: der Name geht als Argument an openssl (kein Shell-Kommando) */
    bool ok = section && section[0] && strlen(section) < sizeof(s_section);
    for (const char *c = section; ok && *c; c++) {
        ok = isalnum((unsigned char)*c) || *c == '_';
    }
    snprintf(s_section, sizeof(s_section), "%s", ok ? section : "tsa_good");
}

/* openssl mit Argumentvektor starten (fork/execvp, keine Shell); stderr nach /dev/null */
static bool run_openssl(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, STDERR_FILENO);
            dup2(dn, STDOUT_FILENO);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int status;
    pid_t w;
    do { /* die FreeRTOS-Linux-Portierung unterbricht mit Tick-Signalen */
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);
    return w == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
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
    char qpath[256], rpath[256], cfg[512];
    snprintf(qpath, sizeof(qpath), "%s/req.tsq", dir);
    snprintf(rpath, sizeof(rpath), "%s/resp.tsr", dir);
    esp_err_t err = ASICS_ERR_TSA_UNAVAILABLE;
    FILE *f = fopen(qpath, "wb");
    if (f) {
        fwrite(req, 1, req_len, f);
        fclose(f);
        snprintf(cfg, sizeof(cfg), "%s/tsa.cnf", pki);
        char *const argv[] = {"openssl", "ts", "-reply", "-config", cfg, "-section", s_section,
                              "-queryfile", qpath, "-out", rpath, NULL};
        if (run_openssl(argv) && (f = fopen(rpath, "rb")) != NULL) {
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
