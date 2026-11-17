# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# ASiC-S Signaturkomponente (asics_signer)
idf_build_get_property(target IDF_TARGET)

set(srcs
    "src/asics_signer.c"
    "src/asics_provision.c"
    "src/asics_container.c"
    "src/zip_writer.c"
    "src/der_writer.c"
    "src/cades_builder.c"
    "src/csr_builder.c"
    "src/cert_store.c"
    "src/time_source.c"
    "src/pem_util.c"
    "src/tsa_req.c"
    "src/asn1_oids.c"
    "src/tsa_resp.c"
    "src/tsa_verify.c"
    "src/tsa.c"
    "src/backend/key_backend.c"
    "src/backend/backend_nvs.c"
    "src/backend/backend_se_stub.c")

if(target STREQUAL "linux")
    # --- Host-Build (Linux-Target, nur fuer Unit-Tests) ----------------------
    # In ESP-IDF 5.2.5 baut die mbedtls-Komponente auf dem linux-Target keine
    # Quelldateien (reine Include-Komponente). Fuer den Host-Test wird daher die
    # mbedtls-Bibliothek (Standardkonfiguration) direkt in diese Komponente
    # hineinkompiliert. NVS wird durch einen RAM-Speicher (kv_ram.c) ersetzt.
    set(mbed_dir "$ENV{IDF_PATH}/components/mbedtls/mbedtls")
    file(GLOB mbed_srcs "${mbed_dir}/library/*.c")
    if(NOT CMAKE_BUILD_EARLY_EXPANSION)
        set_source_files_properties(${mbed_srcs} PROPERTIES COMPILE_OPTIONS "-w")
    endif()
    idf_component_register(
        SRCS ${srcs} "src/kv_ram.c" "src/tsa_host.c" ${mbed_srcs}
        INCLUDE_DIRS "include" "${mbed_dir}/include"
        PRIV_INCLUDE_DIRS "src" "src/backend" "${mbed_dir}/library"
        PRIV_REQUIRES esp_rom esp_hw_support log)
else()
    set(priv_srcs "src/kv_nvs.c" "src/tsa_http.c")
    if(CONFIG_ASICS_ENABLE_CONSOLE)
        list(APPEND priv_srcs "src/console/asics_console.c")
    endif()
    idf_component_register(
        SRCS ${srcs} ${priv_srcs}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src" "src/backend"
        REQUIRES esp_common
        PRIV_REQUIRES mbedtls nvs_flash esp_rom esp_hw_support bootloader_support console log esp_http_client esp-tls)
endif()

# Eingebettete TSA-CA (nur Zielsystem; im Host-Test setzt der Test die CA per asics_tsa_host_set_ca_pem)
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND NOT target STREQUAL "linux" AND NOT "${CONFIG_ASICS_TSA_CA_PEM}" STREQUAL "")
    get_filename_component(asics_tsa_ca_abs "${CONFIG_ASICS_TSA_CA_PEM}" ABSOLUTE BASE_DIR "${PROJECT_DIR}")
    if(NOT EXISTS "${asics_tsa_ca_abs}")
        message(FATAL_ERROR "asics_signer: CONFIG_ASICS_TSA_CA_PEM '${asics_tsa_ca_abs}' nicht gefunden")
    endif()
    configure_file("${asics_tsa_ca_abs}" "${CMAKE_CURRENT_BINARY_DIR}/asics_tsa_ca.pem" COPYONLY)
    target_add_binary_data(${COMPONENT_LIB} "${CMAKE_CURRENT_BINARY_DIR}/asics_tsa_ca.pem" TEXT)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE ASICS_TSA_CA_EMBEDDED=1)
endif()

# Mindest-Zeitpunkt: Standard ist der Zeitpunkt des CMake-Konfigurationslaufs.
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
string(TIMESTAMP asics_build_epoch "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE ASICS_BUILD_TIME_EPOCH=${asics_build_epoch})
endif()
