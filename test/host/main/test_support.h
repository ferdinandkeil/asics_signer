/* Gemeinsame Hilfen der Host-Tests. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "unity.h"
#include "esp_err.h"

#define TEST_TIME ((time_t)1768478400) /* 2026-01-15 12:00:00 UTC */

typedef struct { uint8_t *buf; size_t len; size_t cap; int calls; int fail_at; } sink_t;
esp_err_t sink_write(const void *buf, size_t len, void *ctx);
void sink_free(sink_t *s);
