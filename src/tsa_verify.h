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
#include "mbedtls/x509_crt.h"
#include "tsa_resp.h"

/**
 * @param t        zerlegter Token (tsa_parse_token)
 * @param ca       vertrauenswuerdige TSA-CA (geparst, selbstsigniert oder Zwischen-CA; CA-Flag muss gesetzt sein)
 * @param gen_time genTime aus dem TSTInfo (Gueltigkeitszeitpunkt der Zertifikate)
 * @return ESP_OK oder ASICS_ERR_TSA_INVALID (mit Log-Meldung zum Grund)
 */
esp_err_t tsa_verify_token(const tsa_token_t *t, const mbedtls_x509_crt *ca, time_t gen_time);
