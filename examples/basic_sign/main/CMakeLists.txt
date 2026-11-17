# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
idf_component_register(SRCS "main.c" INCLUDE_DIRS "." REQUIRES asics_signer nvs_flash console mbedtls esp_wifi esp_netif esp_event)
