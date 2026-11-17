/* NVS-Speicher (Zielsystem). NVS muss von der Anwendung initialisiert sein
 * (fuer die Light-Variante: nvs_flash_secure_init mit nvs_keys-Partition). */
#include "kv_store.h"
#include "nvs.h"
#include "sdkconfig.h"

static esp_err_t open_ns(nvs_open_mode_t mode, nvs_handle_t *h)
{
    return nvs_open_from_partition(CONFIG_ASICS_NVS_PARTITION, CONFIG_ASICS_NVS_NAMESPACE, mode, h);
}

esp_err_t asics_kv_init(void)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READWRITE, &h);
    if (err == ESP_OK) {
        nvs_close(h);
    }
    return err;
}

esp_err_t asics_kv_get(const char *key, void *buf, size_t *len)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_ERR_NOT_FOUND; /* Namespace noch nicht angelegt */
    }
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_blob(h, key, buf, len);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_ERR_NOT_FOUND;
    }
    if (err == ESP_ERR_NVS_INVALID_LENGTH) {
        return ESP_ERR_INVALID_SIZE;
    }
    return err;
}

esp_err_t asics_kv_set(const char *key, const void *data, size_t len, bool overwrite)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    if (!overwrite) {
        size_t l = 0;
        esp_err_t e = nvs_get_blob(h, key, NULL, &l);
        if (e == ESP_OK) {
            nvs_close(h);
            return ESP_ERR_INVALID_STATE;
        }
        if (e != ESP_ERR_NVS_NOT_FOUND) {
            nvs_close(h);
            return e;
        }
    }
    err = nvs_set_blob(h, key, data, len);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}
