/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Nur Host-Build: Testhilfen fuer den TSA-Transport. */
#pragma once

#include "asics_signer.h"
#include "tsa_transport.h"

/** Nur Host-Test: Kconfig-Default des TSA-Modus ersetzen (setzt den effektiven Modus zurueck). */
void asics_host_set_tsa_default(asics_tsa_mode_t mode);

/** Test-Hook: ersetzt den Transport vollstaendig (NULL = Standard: openssl ts -reply). */
typedef esp_err_t (*asics_tsa_host_hook_t)(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size,
                                           size_t *resp_len, void *ctx);
void asics_tsa_host_set_hook(asics_tsa_host_hook_t hook, void *ctx);

/** Sektion in tsa.cnf (Verzeichnis aus ASICS_TEST_PKI): "tsa_good" (Standard) oder "tsa_foreign"; nur [A-Za-z0-9_], sonst Standard. */
void asics_tsa_host_set_section(const char *section);

/** Vertrauenswuerdige TSA-CA (PEM-Text, nicht kopiert) fuer den Host-Test; NULL = keine. */
void asics_tsa_host_set_ca_pem(const char *pem);

/** Standardtransport: ruft "openssl ts -reply -config $ASICS_TEST_PKI/tsa.cnf" per fork/execvp (Argumentvektor, keine Shell) auf. */
esp_err_t asics_tsa_host_openssl(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size, size_t *resp_len);
