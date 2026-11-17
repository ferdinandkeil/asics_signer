#include "time_source.h"
#include "sdkconfig.h"

static asics_time_fn_t s_provider;

void asics_time_set_provider(asics_time_fn_t fn)
{
    s_provider = fn;
}

time_t asics_time_min(void)
{
#if CONFIG_ASICS_MIN_TIME > 0
    return (time_t)CONFIG_ASICS_MIN_TIME;
#else
    return (time_t)ASICS_BUILD_TIME_EPOCH;
#endif
}

esp_err_t asics_time_get(time_t *now)
{
    time_t t = s_provider ? s_provider() : time(NULL);
    if (t == (time_t)-1 || t < asics_time_min()) {
        return ESP_ERR_INVALID_STATE;
    }
    *now = t;
    return ESP_OK;
}
