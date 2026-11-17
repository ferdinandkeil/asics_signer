#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_support.h"
#include "mbedtls/base64.h"

void run_zip_tests(void);
void run_cades_tests(void);
void run_csr_tests(void);

esp_err_t sink_write(const void *buf, size_t len, void *ctx)
{
    sink_t *s = ctx;
    s->calls++;
    if (s->fail_at && s->calls >= s->fail_at) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (s->len + len > s->cap) {
        s->cap = (s->len + len) * 2 + 64;
        s->buf = realloc(s->buf, s->cap);
    }
    memcpy(s->buf + s->len, buf, len);
    s->len += len;
    return ESP_OK;
}
void sink_free(sink_t *s) { free(s->buf); memset(s, 0, sizeof(*s)); }

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    TEST_ASSERT_NOT_NULL_MESSAGE(f, path);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(n + 1);
    TEST_ASSERT_EQUAL(n, fread(b, 1, n, f));
    b[n] = 0;
    fclose(f);
    *len = n;
    return b;
}

uint8_t *test_read_pki(const char *name, size_t *len)
{
    const char *dir = getenv("ASICS_TEST_PKI");
    TEST_ASSERT_NOT_NULL_MESSAGE(dir, "ASICS_TEST_PKI nicht gesetzt");
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return read_file(path, len);
}

uint8_t *test_pem_to_der(const char *name, size_t *len)
{
    size_t pl;
    uint8_t *pem = test_read_pki(name, &pl);
    char *b = strstr((char *)pem, "-----BEGIN");
    b = strchr(b, '\n') + 1;
    char *e = strstr(b, "-----END");
    char *clean = malloc(e - b + 1);
    size_t cl = 0;
    for (char *q = b; q < e; q++) if (*q != '\n' && *q != '\r') clean[cl++] = *q;
    uint8_t *der = malloc(cl);
    TEST_ASSERT_EQUAL(0, mbedtls_base64_decode(der, cl, len, (unsigned char *)clean, cl));
    free(clean); free(pem);
    return der;
}

void test_write_out(const char *name, const void *data, size_t len)
{
    const char *dir = getenv("ASICS_TEST_OUT");
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir ? dir : ".", name);
    FILE *f = fopen(path, "wb");
    TEST_ASSERT_NOT_NULL(f);
    fwrite(data, 1, len, f);
    fclose(f);
}

void app_main(void)
{
    UNITY_BEGIN();
    run_zip_tests();
    run_cades_tests();
    run_csr_tests();
    int fails = UNITY_END();
    exit(fails ? 1 : 0);
}
