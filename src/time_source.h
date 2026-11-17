#pragma once
#include <time.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef time_t (*asics_time_fn_t)(void);

/** Ersetzt die Zeitquelle (Standard: time()); fn == NULL stellt time() wieder her. */
void asics_time_set_provider(asics_time_fn_t fn);

/** Mindestzeitpunkt (Kconfig ASICS_MIN_TIME, sonst Build-Zeitpunkt). */
time_t asics_time_min(void);

/** Aktuelle Zeit; ESP_ERR_INVALID_STATE, falls sie unter asics_time_min() liegt. */
esp_err_t asics_time_get(time_t *now);

#ifdef __cplusplus
}
#endif
