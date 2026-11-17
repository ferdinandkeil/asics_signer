#include <string.h>
#include "asics_container.h"
#include "zip_writer.h"

esp_err_t asics_container_check_name(const char *name)
{
    if (!name) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t n = strlen(name);
    if (n == 0 || n > CONFIG_ASICS_PAYLOAD_NAME_MAX || name[0] == '.') {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)name[i];
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\') {
            return ESP_ERR_INVALID_ARG;
        }
    }
    if (strcmp(name, ASICS_MIMETYPE_NAME) == 0 || strncmp(name, "META-INF", 8) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

esp_err_t asics_container_write(const char *payload_name, const uint8_t *data, size_t len,
                                const uint8_t *sig, size_t sig_len, time_t mtime,
                                asics_write_cb_t write, void *ctx)
{
    esp_err_t err = asics_container_check_name(payload_name);
    if (err != ESP_OK || !write || !sig || sig_len == 0 || (!data && len)) {
        return ESP_ERR_INVALID_ARG;
    }
    zip_writer_t zw;
    err = zip_writer_init(&zw, write, ctx, mtime);
    if (err != ESP_OK) {
        return err;
    }
    err = zip_writer_add_stored(&zw, ASICS_MIMETYPE_NAME, (const uint8_t *)ASICS_MIMETYPE_VALUE,
                                strlen(ASICS_MIMETYPE_VALUE));
    if (err == ESP_OK) {
        err = zip_writer_add_stored(&zw, payload_name, data, len);
    }
    if (err == ESP_OK) {
        err = zip_writer_add_stored(&zw, ASICS_SIGNATURE_NAME, sig, sig_len);
    }
    if (err == ESP_OK) {
        err = zip_writer_finish(&zw);
    }
    return err;
}
