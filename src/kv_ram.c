/* RAM-Speicher fuer den Host-Test (linux-Target). */
#include <stdlib.h>
#include <string.h>
#include "kv_store.h"

#define MAXE 8
static struct { char key[16]; uint8_t *data; size_t len; } s_e[MAXE];

void asics_kv_ram_reset(void)
{
    for (int i = 0; i < MAXE; i++) {
        free(s_e[i].data);
        memset(&s_e[i], 0, sizeof(s_e[i]));
    }
}

esp_err_t asics_kv_init(void) { return ESP_OK; }

static int find(const char *key)
{
    for (int i = 0; i < MAXE; i++) {
        if (s_e[i].data && strcmp(s_e[i].key, key) == 0) {
            return i;
        }
    }
    return -1;
}

esp_err_t asics_kv_get(const char *key, void *buf, size_t *len)
{
    int i = find(key);
    if (i < 0) {
        return ESP_ERR_NOT_FOUND;
    }
    if (!buf) {
        *len = s_e[i].len;
        return ESP_OK;
    }
    if (*len < s_e[i].len) {
        *len = s_e[i].len;
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(buf, s_e[i].data, s_e[i].len);
    *len = s_e[i].len;
    return ESP_OK;
}

esp_err_t asics_kv_set(const char *key, const void *data, size_t len, bool overwrite)
{
    int i = find(key);
    if (i >= 0 && !overwrite) {
        return ESP_ERR_INVALID_STATE;
    }
    if (i < 0) {
        for (int k = 0; k < MAXE; k++) {
            if (!s_e[k].data) { i = k; break; }
        }
        if (i < 0 || strlen(key) >= sizeof(s_e[0].key)) {
            return ESP_ERR_NO_MEM;
        }
        strcpy(s_e[i].key, key);
    }
    uint8_t *n = malloc(len ? len : 1);
    if (!n) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(n, data, len);
    free(s_e[i].data);
    s_e[i].data = n;
    s_e[i].len = len;
    return ESP_OK;
}
