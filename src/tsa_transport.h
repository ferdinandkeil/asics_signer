/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Nicht-oeffentliche Trennstelle fuer den Transport von TimeStampReq/-Resp.
 * Zielsystem: tsa_http.c (esp_http_client); Host-Test: tsa_host.c (openssl ts -reply).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/**
 * Sendet req (DER-TimeStampReq) an die TSA und schreibt die Antwort (DER-TimeStampResp) nach resp.
 * @return ESP_OK; ASICS_ERR_TSA_UNAVAILABLE bei Netz-/Timeout-/HTTP-Fehlern;
 *         ESP_ERR_NO_MEM, wenn die Antwort nicht in resp_size passt.
 */
esp_err_t asics_tsa_transport(const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_size, size_t *resp_len);
