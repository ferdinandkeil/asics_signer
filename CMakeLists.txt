# ASiC-S Signaturkomponente (asics_signer)
idf_build_get_property(target IDF_TARGET)

set(srcs)

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
        SRCS ${srcs} ${mbed_srcs}
        INCLUDE_DIRS "include" "${mbed_dir}/include"
        PRIV_INCLUDE_DIRS "src" "${mbed_dir}/library"
        PRIV_REQUIRES esp_rom esp_hw_support log)
else()
    idf_component_register(
        SRCS ${srcs}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src"
        REQUIRES esp_common
        PRIV_REQUIRES mbedtls nvs_flash esp_rom esp_hw_support bootloader_support console log)
endif()

# Mindest-Zeitpunkt: Standard ist der Zeitpunkt des CMake-Konfigurationslaufs.
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
string(TIMESTAMP asics_build_epoch "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE ASICS_BUILD_TIME_EPOCH=${asics_build_epoch})
endif()
