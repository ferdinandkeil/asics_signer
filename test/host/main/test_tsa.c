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
#include "tsa_verify.h"

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

/* ---- Token-Pruefung (Signatur, ESS, TSA-Zertifikat) ---- */
static esp_err_t verify_exchange(exch_t *x, const char *ca_pem, time_t gen_time_override, bool use_override)
{
    tsa_resp_t r;
    tsa_token_t t;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(x->resp, x->resp_len, &r));
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(r.token, r.token_len, &t));
    time_t gt = 0;
    tsa_expect_t e = expect_of(x, time(NULL), 300);
    TEST_ASSERT_EQUAL(ESP_OK, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    size_t cl;
    uint8_t *ca = test_pem_to_der(ca_pem, &cl);
    esp_err_t err = tsa_verify_token(&t, ca, cl, use_override ? gen_time_override : gt);
    free(ca);
    return err;
}

static void test_tsa_verify_good(void)
{
    exch_t x;
    exchange(&x, 0x66);
    TEST_ASSERT_EQUAL(ESP_OK, verify_exchange(&x, "tsa_root.pem", 0, false));
    /* gueltig zur genTime: davor/danach (Zertifikate 2024..2044) nicht */
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_exchange(&x, "tsa_root.pem", (time_t)1600000000, true));
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_exchange(&x, "tsa_root.pem", (time_t)2600000000LL, true));
}

static void test_tsa_verify_negative(void)
{
    exch_t x;
    /* falsche (fremde) TSA-CA als Vertrauensanker */
    exchange(&x, 0x67);
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_exchange(&x, "tsa_root2.pem", 0, false));
    /* TSA-Zertifikat von fremder CA (Antwort aus Sektion tsa_foreign), gegen tsa_root geprueft */
    exchange(&x, 0x68);
    uint8_t req[128];
    size_t rl;
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_build_request(x.digest, x.nonce, NULL, req, sizeof(req), &rl));
    asics_tsa_host_set_section("tsa_foreign");
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_transport(req, rl, x.resp, sizeof(x.resp), &x.resp_len));
    asics_tsa_host_set_section("tsa_good");
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_exchange(&x, "tsa_root.pem", 0, false));
    TEST_ASSERT_EQUAL(ESP_OK, verify_exchange(&x, "tsa_root2.pem", 0, false));   /* Gegenprobe: mit passender CA ok */

    /* manipulierte Signatur: letztes Signaturbyte (Token endet mit der Signatur) */
    exchange(&x, 0x69);
    tsa_resp_t r;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(x.resp, x.resp_len, &r));
    ((uint8_t *)r.token)[r.token_len - 3] ^= 0x01;
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_exchange(&x, "tsa_root.pem", 0, false));

    /* manipulierter TSTInfo (message-digest im signierten Attribut stimmt nicht mehr): letztes TSTInfo-Byte (Nonce) */
    exchange(&x, 0x6A);
    tsa_token_t t;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(x.resp, x.resp_len, &r));
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(r.token, r.token_len, &t));
    ((uint8_t *)t.tstinfo)[t.tstinfo_len - 1] ^= 0x01;
    size_t cl;
    uint8_t *ca = test_pem_to_der("tsa_root.pem", &cl);
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, tsa_verify_token(&t, ca, cl, time(NULL)));
    free(ca);
}

/* Eigene Token per openssl cms -sign (TSTInfo der Test-TSA, anderes Signaturzertifikat) */
static size_t cms_token(const exch_t *x, const char *cert, const char *key, uint8_t *out, size_t cap)
{
    tsa_resp_t r;
    tsa_token_t t;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(x->resp, x->resp_len, &r));
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(r.token, r.token_len, &t));
    const char *pki = getenv("ASICS_TEST_PKI");
    char dir[] = "/tmp/asics_cms_XXXXXX", in[256], tok[256], cmd[1200];
    TEST_ASSERT_NOT_NULL(mkdtemp(dir));
    snprintf(in, sizeof(in), "%s/tst.der", dir);
    snprintf(tok, sizeof(tok), "%s/tok.der", dir);
    FILE *f = fopen(in, "wb");
    fwrite(t.tstinfo, 1, t.tstinfo_len, f);
    fclose(f);
    snprintf(cmd, sizeof(cmd),
             "openssl cms -sign -binary -nodetach -outform DER -in %s -econtent_type 1.2.840.113549.1.9.16.1.4 "
             "-signer %s/%s -inkey %s/%s -certfile %s/tsa_root.pem -md sha256 -cades -out %s 2>/dev/null",
             in, pki, cert, pki, key, pki, tok);
    TEST_ASSERT_EQUAL(0, system(cmd));
    f = fopen(tok, "rb");
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    TEST_ASSERT_EQUAL(0, system(cmd));
    return n;
}

static esp_err_t verify_custom(const exch_t *x, const char *cert, const char *key)
{
    static uint8_t tok[8192];
    size_t n = cms_token(x, cert, key, tok, sizeof(tok));
    tsa_token_t t;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(tok, n, &t));
    size_t cl;
    uint8_t *ca = test_pem_to_der("tsa_root.pem", &cl);
    esp_err_t e = tsa_verify_token(&t, ca, cl, time(NULL));
    free(ca);
    return e;
}

static void test_tsa_verify_certificates(void)
{
    exch_t x;
    exchange(&x, 0x6B);
    TEST_ASSERT_EQUAL(ESP_OK, verify_custom(&x, "tsa.pem", "tsa.key"));              /* Kontrolle: EC mit EKU */
    TEST_ASSERT_EQUAL(ESP_OK, verify_custom(&x, "tsa_rsa.pem", "tsa_rsa.key"));      /* RSA PKCS#1 v1.5 */
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_custom(&x, "tsa_noeku.pem", "tsa.key"));   /* ohne EKU */
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_custom(&x, "tsa_foreign.pem", "tsa.key")); /* fremde CA */
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_INVALID, verify_custom(&x, "dev.pem", "dev.key"));         /* Geraetezertifikat: keine EKU */
}

void run_tsa_tests(void)
{
    RUN_TEST(test_tsa_request_vectors);
    RUN_TEST(test_tsa_request_errors);
    RUN_TEST(test_tsa_host_transport);
    RUN_TEST(test_tsa_resp_good);
    RUN_TEST(test_tsa_resp_bad_structure);
    RUN_TEST(test_tsa_generalized_time);
    RUN_TEST(test_tsa_verify_good);
    RUN_TEST(test_tsa_verify_negative);
    RUN_TEST(test_tsa_verify_certificates);
}
