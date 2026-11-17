/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include "asics_internal.h"
#include "asics_signer.h"

/** Prueft den Nutzdateinamen (ASCII/UTF-8, kein Pfad, nicht reserviert). */
esp_err_t asics_container_check_name(const char *name);

/**
 * Schreibt den Container: mimetype, Nutzdatei, META-INF/signature.p7s (alle STORE).
 * Ein Callback-Fehler bricht ab und wird zurueckgegeben.
 */
esp_err_t asics_container_write(const char *payload_name, const uint8_t *data, size_t len,
                                const uint8_t *sig, size_t sig_len, time_t mtime,
                                asics_write_cb_t write, void *ctx);
