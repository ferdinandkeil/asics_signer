/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Minimaler Blob-Speicher (Namespace per Kconfig). Auf dem Ziel NVS (kv_nvs.c),
 * im Host-Test ein RAM-Speicher (kv_ram.c).
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

esp_err_t asics_kv_init(void);
/** buf == NULL: nur Laenge ermitteln. ESP_ERR_NOT_FOUND, ESP_ERR_NVS_INVALID_LENGTH-artig -> ESP_ERR_INVALID_SIZE. */
esp_err_t asics_kv_get(const char *key, void *buf, size_t *len);
/** overwrite == false: existiert der Schluessel, wird ESP_ERR_INVALID_STATE geliefert. */
esp_err_t asics_kv_set(const char *key, const void *data, size_t len, bool overwrite);

/** Nur Host-Test (kv_ram.c): Speicher leeren. */
void asics_kv_ram_reset(void);
