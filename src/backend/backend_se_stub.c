/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Stub fuer ein externes Secure Element / TPM 2.0: nicht implementiert. */
#include "sdkconfig.h"
#include "key_backend.h"

#if CONFIG_ASICS_KEY_BACKEND_SE_STUB
esp_err_t asics_key_init(void) { return ESP_ERR_NOT_SUPPORTED; }
bool asics_key_has_key(void) { return false; }
esp_err_t asics_key_generate(void) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t asics_key_get_public(uint8_t pub[65]) { (void)pub; return ESP_ERR_NOT_SUPPORTED; }
esp_err_t asics_key_sign_digest(const uint8_t digest[32], uint8_t *sig, size_t sig_size, size_t *sig_len)
{
    (void)digest; (void)sig; (void)sig_size; (void)sig_len;
    return ESP_ERR_NOT_SUPPORTED;
}
#endif
