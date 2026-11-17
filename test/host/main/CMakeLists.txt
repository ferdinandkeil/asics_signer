idf_component_register(
    SRCS "test_main.c" "test_zip.c" "test_cades.c" "test_csr.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS "../../../src" "../../../src/backend"
    REQUIRES unity asics_signer esp_rom)
