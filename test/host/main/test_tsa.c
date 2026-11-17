/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_support.h"
#include "asics_signer.h"
#include "tsa_req.h"
#include "tsa_host.h"

static size_t unhex(const char *h, uint8_t *out)
{
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void check_req(const uint8_t *nonce, const char *policy, const char *expect_hex)
{
    uint8_t digest[32], want[128], got[128];
    memset(digest, 0x11, sizeof(digest));
    size_t n = 0, wn = unhex(expect_hex, want);
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_build_request(digest, nonce, policy, got, sizeof(got), &n));
    TEST_ASSERT_EQUAL(wn, n);
    TEST_ASSERT_EQUAL_MEMORY(want, got, n);
}

/* Feste Vektoren: Nonce-Kodierung (minimal, positiv), optionale reqPolicy, certReq TRUE */
static void test_tsa_request_vectors(void)
{
    const uint8_t n1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t n2[8] = {0, 0, 0, 0, 0, 0, 0, 0xff};
    const uint8_t n3[8] = {0x80, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t n4[8] = {0};
    check_req(n1, NULL, "30430201013031300d0609608648016503040201050004201111111111111111111111111111111111111111111111111111111111111111020801020304050607080101ff");
    check_req(n1, "", "30430201013031300d0609608648016503040201050004201111111111111111111111111111111111111111111111111111111111111111020801020304050607080101ff");
    check_req(n2, "1.2.3.4", "30420201013031300d060960864801650304020105000420111111111111111111111111111111111111111111111111111111111111111106032a0304020200ff0101ff");
    check_req(n3, NULL, "30440201013031300d060960864801650304020105000420111111111111111111111111111111111111111111111111111111111111111102090080000000000000010101ff");
    check_req(n4, NULL, "303c0201013031300d06096086480165030402010500042011111111111111111111111111111111111111111111111111111111111111110201000101ff");
}

static void test_tsa_request_errors(void)
{
    uint8_t digest[32] = {0}, nonce[8] = {1}, buf[200], tiny[20];
    size_t n;
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, asics_tsa_build_request(digest, nonce, NULL, tiny, sizeof(tiny), &n));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_tsa_build_request(digest, nonce, "kein.oid", buf, sizeof(buf), &n));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_tsa_build_request(NULL, nonce, NULL, buf, sizeof(buf), &n));
    /* Ergebnis fuer die externe Pruefung (openssl ts -query -text) ablegen */
    const uint8_t nn[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    memset(digest, 0x11, sizeof(digest));
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_build_request(digest, nn, "1.2.3.4", buf, sizeof(buf), &n));
    test_write_out("tsa_request.tsq", buf, n);
}

/* Host-Transport: openssl ts -reply beantwortet die Anfrage; Hook ersetzt/stoert den Transport */
static esp_err_t fail_hook(const uint8_t *req, size_t rl, uint8_t *resp, size_t rs, size_t *n, void *ctx)
{
    (void)req; (void)rl; (void)resp; (void)rs; (void)n; (*(int *)ctx)++;
    return ASICS_ERR_TSA_UNAVAILABLE;
}

static void test_tsa_host_transport(void)
{
    uint8_t digest[32], nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8}, req[128], resp[4096];
    memset(digest, 0x22, sizeof(digest));
    size_t rl, n;
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_build_request(digest, nonce, NULL, req, sizeof(req), &rl));
    asics_tsa_host_set_hook(NULL, NULL);
    asics_tsa_host_set_section("tsa_good");
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_transport(req, rl, resp, sizeof(resp), &n));
    TEST_ASSERT_TRUE(n > 200 && resp[0] == 0x30);
    test_write_out("tsa_reply.tsr", resp, n);
    test_write_out("tsa_reply_request.tsq", req, rl);
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, asics_tsa_transport(req, rl, resp, 100, &n));   /* Antwort zu gross */
    /* fremde TSA-Sektion antwortet ebenfalls */
    asics_tsa_host_set_section("tsa_foreign");
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_transport(req, rl, resp, sizeof(resp), &n));
    asics_tsa_host_set_section("tsa_good");
    /* Hook */
    int calls = 0;
    asics_tsa_host_set_hook(fail_hook, &calls);
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_UNAVAILABLE, asics_tsa_transport(req, rl, resp, sizeof(resp), &n));
    TEST_ASSERT_EQUAL(1, calls);
    asics_tsa_host_set_hook(NULL, NULL);
}

void run_tsa_tests(void)
{
    RUN_TEST(test_tsa_request_vectors);
    RUN_TEST(test_tsa_request_errors);
    RUN_TEST(test_tsa_host_transport);
}
