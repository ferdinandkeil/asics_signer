#include <string.h>
#include <stdlib.h>
#include "test_support.h"
#include "kv_store.h"
#include "backend/key_backend.h"

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
    /* Signatur pruefbar */
    uint8_t dg[32] = {1}, sig[80]; size_t sl;
    TEST_ASSERT_EQUAL(ESP_OK, asics_key_sign_digest(dg, sig, sizeof(sig), &sl));
    TEST_ASSERT_TRUE(sl >= 8 && sl <= 72 && sig[0] == 0x30);
}

void run_csr_tests(void)
{
    RUN_TEST(test_key_generate_never_replaces);
}
