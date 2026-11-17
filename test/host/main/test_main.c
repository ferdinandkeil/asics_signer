#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_support.h"

void run_zip_tests(void);

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

void app_main(void)
{
    UNITY_BEGIN();
    run_zip_tests();
    int fails = UNITY_END();
    exit(fails ? 1 : 0);
}
