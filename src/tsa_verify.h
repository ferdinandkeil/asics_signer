/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Pruefung eines TimeStampTokens (RFC 3161 / CMS): Signatur, ESS-Bindung an das TSA-Zertifikat,
 * TSA-Zertifikat (kritische EKU timeStamping, Kette zur eingebetteten TSA-CA, Gueltigkeit zur genTime).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "esp_err.h"
#include "tsa_resp.h"

/**
 * @param t        zerlegter Token (tsa_parse_token)
 * @param ca_der   vertrauenswuerdige TSA-CA (DER, selbstsigniert oder Zwischen-CA mit CA-Flag)
 * @param gen_time genTime aus dem TSTInfo (Gueltigkeitszeitpunkt der Zertifikate)
 * @return ESP_OK oder ASICS_ERR_TSA_INVALID (mit Log-Meldung zum Grund)
 */
esp_err_t tsa_verify_token(const tsa_token_t *t, const uint8_t *ca_der, size_t ca_len, time_t gen_time);
