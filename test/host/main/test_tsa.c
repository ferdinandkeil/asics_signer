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
#include "tsa_resp.h"

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

/* ---- Antwort-Parser und TSTInfo-Pruefung (Antworten von openssl ts -reply) ---- */
typedef struct {
    uint8_t digest[32], nonce[8];
    uint8_t resp[4096];
    size_t resp_len;
} exch_t;

static void exchange(exch_t *x, uint8_t fill)
{
    uint8_t req[128];
    size_t rl;
    memset(x->digest, fill, 32);
    for (int i = 0; i < 8; i++) x->nonce[i] = (uint8_t)(0x70 + i);
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_build_request(x->digest, x->nonce, NULL, req, sizeof(req), &rl));
    asics_tsa_host_set_hook(NULL, NULL);
    asics_tsa_host_set_section("tsa_good");
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_transport(req, rl, x->resp, sizeof(x->resp), &x->resp_len));
}

static tsa_expect_t expect_of(const exch_t *x, time_t now, unsigned tol)
{
    return (tsa_expect_t){.digest = x->digest, .nonce = x->nonce, .nonce_len = 8, .now = now, .tolerance_s = tol};
}

static void test_tsa_resp_good(void)
{
    exch_t x;
    exchange(&x, 0x33);
    tsa_resp_t r;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(x.resp, x.resp_len, &r));
    TEST_ASSERT_EQUAL_HEX8(0x30, r.token[0]);
    tsa_token_t t;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(r.token, r.token_len, &t));
    TEST_ASSERT_TRUE(t.tstinfo_len > 40);
    time_t now = time(NULL), gt = 0;
    tsa_expect_t e = expect_of(&x, now, 300);
    TEST_ASSERT_EQUAL(ESP_OK, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    TEST_ASSERT_TRUE(gt >= now - 5 && gt <= now + 5);
    /* genTime-Toleranz */
    e = expect_of(&x, now + 1000, 300);
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    e = expect_of(&x, now - 1000, 300);
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    e = expect_of(&x, now + 1000, 3000);
    TEST_ASSERT_EQUAL(ESP_OK, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    /* falscher Imprint / falsche Nonce */
    uint8_t other[32];
    memset(other, 0x44, sizeof(other));
    e = expect_of(&x, now, 300);
    e.digest = other;
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    uint8_t n2[8] = {0};
    e = expect_of(&x, now, 300);
    e.nonce = n2;
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    /* verkuerzte Nonce (Praefix) darf nicht passen */
    e = expect_of(&x, now, 300);
    e.nonce_len = 7;
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
}

static void test_tsa_resp_bad_structure(void)
{
    exch_t x;
    exchange(&x, 0x55);
    tsa_resp_t r;
    /* abgeschnitten / Rest / Muell */
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_parse_response(x.resp, x.resp_len - 10, &r));
    x.resp[x.resp_len] = 0;
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_parse_response(x.resp, x.resp_len + 1, &r));
    const uint8_t junk[] = {0xff, 0x00, 0x01};
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_parse_response(junk, sizeof(junk), &r));
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_parse_response(x.resp, 0, &r));
    /* Status rejection(2) ohne Token */
    const uint8_t rej[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02};
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_REJECTED, tsa_parse_response(rej, sizeof(rej), &r));
    /* granted(0) aber kein Token */
    const uint8_t notok[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00};
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_parse_response(notok, sizeof(notok), &r));
    /* Token kaputt: eContentType veraendert */
    exchange(&x, 0x55);
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(x.resp, x.resp_len, &r));
    uint8_t *tok = (uint8_t *)r.token;
    tsa_token_t t;
    for (size_t i = 0; i + 13 < r.token_len; i++) {   /* id-ct-TSTInfo-OID finden und zerstoeren */
        if (tok[i] == 0x06 && tok[i + 1] == 0x0B && tok[i + 10] == 0x10 && tok[i + 12] == 0x04) {
            tok[i + 12] = 0x05;
            break;
        }
    }
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_parse_token(r.token, r.token_len, &t));
}

static void test_tsa_generalized_time(void)
{
    time_t t;
    TEST_ASSERT_TRUE(tsa_parse_generalized_time((const uint8_t *)"20260115120000Z", 15, &t));
    TEST_ASSERT_EQUAL(1768478400, t);
    TEST_ASSERT_TRUE(tsa_parse_generalized_time((const uint8_t *)"20260115120000.123Z", 19, &t));
    TEST_ASSERT_EQUAL(1768478400, t);
    TEST_ASSERT_TRUE(tsa_parse_generalized_time((const uint8_t *)"19700101000000Z", 15, &t));
    TEST_ASSERT_EQUAL(0, t);
    TEST_ASSERT_FALSE(tsa_parse_generalized_time((const uint8_t *)"20260115120000", 14, &t));
    TEST_ASSERT_FALSE(tsa_parse_generalized_time((const uint8_t *)"2026011512000aZ", 15, &t));
    TEST_ASSERT_FALSE(tsa_parse_generalized_time((const uint8_t *)"20261315120000Z", 15, &t));
    TEST_ASSERT_FALSE(tsa_parse_generalized_time((const uint8_t *)"20260115120000.Z", 16, &t));
}

void run_tsa_tests(void)
{
    RUN_TEST(test_tsa_request_vectors);
    RUN_TEST(test_tsa_request_errors);
    RUN_TEST(test_tsa_host_transport);
    RUN_TEST(test_tsa_resp_good);
    RUN_TEST(test_tsa_resp_bad_structure);
    RUN_TEST(test_tsa_generalized_time);
}
