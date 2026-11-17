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
        SRCS ${srcs} "src/kv_ram.c" ${mbed_srcs}
        INCLUDE_DIRS "include" "${mbed_dir}/include"
        PRIV_INCLUDE_DIRS "src" "src/backend" "${mbed_dir}/library"
        PRIV_REQUIRES esp_rom esp_hw_support log)
else()
    set(priv_srcs "src/kv_nvs.c")
    idf_component_register(
        SRCS ${srcs} ${priv_srcs}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src" "src/backend"
        REQUIRES esp_common
        PRIV_REQUIRES mbedtls nvs_flash esp_rom esp_hw_support bootloader_support console log)
endif()

# Mindest-Zeitpunkt: Standard ist der Zeitpunkt des CMake-Konfigurationslaufs.
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
string(TIMESTAMP asics_build_epoch "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE ASICS_BUILD_TIME_EPOCH=${asics_build_epoch})
endif()
