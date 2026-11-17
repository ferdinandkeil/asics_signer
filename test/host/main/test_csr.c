#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_support.h"
#include "asics_signer.h"
#include "asics_provision.h"
#include "csr_builder.h"
#include "kv_store.h"
#include "pem_util.h"
#include "backend/key_backend.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/sha256.h"

static void verify_csr(const uint8_t *der, size_t n, const char *expect_subject)
{
    mbedtls_x509_csr csr;
    mbedtls_x509_csr_init(&csr);
    TEST_ASSERT_EQUAL(0, mbedtls_x509_csr_parse_der(&csr, der, n));
    char dn[256];
    mbedtls_x509_dn_gets(dn, sizeof(dn), &csr.subject);
    TEST_ASSERT_EQUAL_STRING(expect_subject, dn);
    uint8_t h[32];
    mbedtls_sha256(csr.cri.p, csr.cri.len, h, 0);
    TEST_ASSERT_EQUAL(0, mbedtls_pk_verify(&csr.pk, MBEDTLS_MD_SHA256, h, 32, csr.sig.p, csr.sig.len));
    mbedtls_x509_csr_free(&csr);
}

static void test_csr_structure(void)
{
    test_install_device_key();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&(asics_config_t){.device_serial = "SN-1"}));
    uint8_t der[CONFIG_ASICS_CSR_BUF_SIZE];
    size_t n;
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_create_csr(der, sizeof(der), &n));
    verify_csr(der, n, "C=DE, O=Test Org, serialNumber=SN-1, CN=020000000001");
    TEST_ASSERT_EQUAL_HEX8(0x30, der[0]);

    /* Public Key im CSR == Schluessel */
    uint8_t pub[65];
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_get_public_key(pub));
    bool found = false;
    for (size_t i = 0; i + 65 <= n; i++) if (!memcmp(der + i, pub, 65)) found = true;
    TEST_ASSERT_TRUE(found);

    char pem[CONFIG_ASICS_CSR_BUF_SIZE * 2];
    size_t pl;
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_create_csr_pem(pem, sizeof(pem), &pl));
    TEST_ASSERT_EQUAL_MEMORY("-----BEGIN CERTIFICATE REQUEST-----\n", pem, 36);
    test_write_out("device.csr.pem", pem, pl);
    uint8_t d2[CONFIG_ASICS_CSR_BUF_SIZE];
    size_t n2;
    TEST_ASSERT_EQUAL(ESP_OK, asics_pem_decode("CERTIFICATE REQUEST", pem, pl, d2, sizeof(d2), &n2));
    TEST_ASSERT_EQUAL(n, n2);
    TEST_ASSERT_EQUAL_MEMORY(der, d2, n);
}

static void test_csr_without_serial(void)
{
    test_install_device_key();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&(asics_config_t){.device_serial = ""}));
    uint8_t der[CONFIG_ASICS_CSR_BUF_SIZE];
    size_t n;
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_create_csr(der, sizeof(der), &n));
    verify_csr(der, n, "C=DE, O=Test Org, CN=020000000001");
}

static void test_csr_validation(void)
{
    csr_params_t p = {.cn = "AABBCCDDEEFF", .serial = "bad;serial", .sign = NULL};
    uint8_t out[512]; size_t n;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, csr_build(&p, out, sizeof(out), &n));
    test_install_device_key();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_provision_set_serial("1234567890123456789012345678901234567890123456789012345678901234567890"));
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_set_serial("bad;serial"));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_provision_create_csr(out, sizeof(out), &n));
    asics_provision_set_serial("");
    uint8_t tiny[100];
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, asics_provision_create_csr(tiny, sizeof(tiny), &n));
}

static void test_key_generate_never_replaces(void)
{
    asics_kv_ram_reset();
    TEST_ASSERT_FALSE(asics_key_has_key());
    TEST_ASSERT_EQUAL(ESP_OK, asics_key_generate());
    TEST_ASSERT_TRUE(asics_key_has_key());
    uint8_t pub1[65], pub2[65];
    TEST_ASSERT_EQUAL(ESP_OK, asics_key_get_public(pub1));
    TEST_ASSERT_EQUAL_HEX8(0x04, pub1[0]);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_key_generate());
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_kv_set("key", "x", 1, false));
    TEST_ASSERT_EQUAL(ESP_OK, asics_key_get_public(pub2));
    TEST_ASSERT_EQUAL_MEMORY(pub1, pub2, 65);
    /* init mit AUTO_GENERATE aendert vorhandenen Schluessel nicht */
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));
    TEST_ASSERT_EQUAL(ESP_OK, asics_key_get_public(pub2));
    TEST_ASSERT_EQUAL_MEMORY(pub1, pub2, 65);
    /* Signatur pruefbar */
    uint8_t dg[32] = {1}, sig[80]; size_t sl;
    TEST_ASSERT_EQUAL(ESP_OK, asics_key_sign_digest(dg, sig, sizeof(sig), &sl));
    TEST_ASSERT_TRUE(sl >= 8 && sl <= 72 && sig[0] == 0x30);
}

void run_csr_tests(void)
{
    RUN_TEST(test_csr_structure);
    RUN_TEST(test_csr_without_serial);
    RUN_TEST(test_csr_validation);
    RUN_TEST(test_key_generate_never_replaces);
}
