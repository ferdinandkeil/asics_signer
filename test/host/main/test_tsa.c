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
#include "asics_provision.h"
#include "time_source.h"

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

/* ---- Integration: asics_sign_ex mit TSA-Modi ---- */
static time_t g_dev_offset;
static time_t real_clock(void) { return time(NULL) + g_dev_offset; }

typedef struct {
    uint8_t *buf;
    size_t len;
} blob_t;

static char *s_ca_pem;

static void tsa_setup(asics_tsa_mode_t mode)
{
    g_dev_offset = 0;
    asics_time_set_provider(real_clock);
    asics_tsa_host_set_hook(NULL, NULL);
    asics_tsa_host_set_section("tsa_good");
    if (!s_ca_pem) {
        size_t n;
        s_ca_pem = (char *)test_read_pki("tsa_root.pem", &n);
    }
    asics_tsa_host_set_ca_pem(s_ca_pem);
    test_install_device_key();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&(asics_config_t){.tsa_mode = mode}));
    test_load_certs("dev.pem", "ca.pem");
}

static bool contains(const uint8_t *buf, size_t n, const uint8_t *pat, size_t pl)
{
    for (size_t i = 0; i + pl <= n; i++) {
        if (!memcmp(buf + i, pat, pl)) return true;
    }
    return false;
}

static const uint8_t OID_STS[] = {0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E};

static void test_tsa_sign_modes_ok(void)
{
    static const uint8_t data[] = "zeit;wert\n2026-01-15T12:00:00Z;42,5\n";   /* = messung.csv der Ende-zu-Ende-Tests */
    asics_sign_result_t res;
    for (int pass = 0; pass < 2; pass++) {
        tsa_setup(pass ? ASICS_TSA_REQUIRED : ASICS_TSA_PREFERRED);
        sink_t s = {0};
        TEST_ASSERT_EQUAL(pass ? ASICS_TSA_REQUIRED : ASICS_TSA_PREFERRED, asics_get_tsa_mode());
        TEST_ASSERT_EQUAL(ESP_OK, asics_sign_ex("messung.csv", data, sizeof(data) - 1, sink_write, &s, &res));
        TEST_ASSERT_EQUAL(ASICS_LEVEL_B_T, res.level);
        TEST_ASSERT_EQUAL(ESP_OK, res.tsa_err);
        TEST_ASSERT_TRUE(llabs((long long)(res.tsa_gen_time - time(NULL))) < 10);
        TEST_ASSERT_TRUE(contains(s.buf, s.len, OID_STS, sizeof(OID_STS)));
        test_write_out(pass ? "sample_tsa_required.asics" : "sample_tsa.asics", s.buf, s.len);
        sink_free(&s);
    }
    /* OFF: B-B, kein Token, TSA wird nicht kontaktiert */
    tsa_setup(ASICS_TSA_OFF);
    int calls = 0;
    asics_tsa_host_set_hook(fail_hook, &calls);
    sink_t s = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign_ex("t.csv", data, sizeof(data) - 1, sink_write, &s, &res));
    TEST_ASSERT_EQUAL(ASICS_LEVEL_B_B, res.level);
    TEST_ASSERT_EQUAL(ESP_OK, res.tsa_err);
    TEST_ASSERT_EQUAL(0, calls);
    TEST_ASSERT_FALSE(contains(s.buf, s.len, OID_STS, sizeof(OID_STS)));
    sink_free(&s);
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("t.csv", data, sizeof(data) - 1, sink_write, &s));   /* ohne res */
    sink_free(&s);
    asics_tsa_host_set_hook(NULL, NULL);
}

/* ---- Negativfaelle: Hook liefert eine defekte/abgelehnte Antwort ---- */
typedef enum {
    F_TRANSPORT, F_REJECTED, F_IMPRINT, F_NONCE, F_SIGNATURE, F_TSTINFO, F_FOREIGN_CA, F_NO_EKU,
    F_TRUNCATED, F_TOO_BIG, F_NO_TOKEN, F_CLOCK, F_NO_CA, F_COUNT
} fault_t;

static fault_t g_fault;

/* TimeStampResp aus Token bauen: SEQ { SEQ { INTEGER 0 }, token } */
static size_t wrap_resp(const uint8_t *tok, size_t n, uint8_t *out)
{
    size_t o = 0;
    static const uint8_t st[] = {0x30, 0x03, 0x02, 0x01, 0x00};
    size_t body = sizeof(st) + n;
    out[o++] = 0x30;
    out[o++] = 0x82;
    out[o++] = (uint8_t)(body >> 8);
    out[o++] = (uint8_t)body;
    memcpy(out + o, st, sizeof(st)); o += sizeof(st);
    memcpy(out + o, tok, n); o += n;
    return o;
}

static esp_err_t fault_hook(const uint8_t *req, size_t rl, uint8_t *resp, size_t rs, size_t *n, void *ctx)
{
    (void)ctx;
    uint8_t q[160];
    memcpy(q, req, rl);
    switch (g_fault) {
    case F_TRANSPORT:
        return ASICS_ERR_TSA_UNAVAILABLE;
    case F_TOO_BIG:
        return ESP_ERR_NO_MEM;
    case F_REJECTED: {
        static const uint8_t rej[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02};
        memcpy(resp, rej, sizeof(rej));
        *n = sizeof(rej);
        return ESP_OK;
    }
    case F_IMPRINT:
        q[27] ^= 0x01;                    /* Digest-Byte der Anfrage: Antwort bestaetigt einen anderen Imprint */
        break;
    case F_NONCE:
        q[rl - 5] ^= 0x01;                /* Nonce-Byte (vor certReq TRUE) */
        break;
    case F_FOREIGN_CA:
        asics_tsa_host_set_section("tsa_foreign");
        break;
    default:
        break;
    }
    esp_err_t e = asics_tsa_host_openssl(q, rl, resp, rs, n);
    asics_tsa_host_set_section("tsa_good");
    if (e != ESP_OK) return e;
    tsa_resp_t r;
    tsa_token_t t;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(resp, *n, &r));
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(r.token, r.token_len, &t));
    switch (g_fault) {
    case F_SIGNATURE:
        ((uint8_t *)r.token)[r.token_len - 3] ^= 0x01;
        break;
    case F_TSTINFO:
        ((uint8_t *)t.tstinfo)[t.tstinfo_len - 1] ^= 0x01;   /* Nonce im TSTInfo: message-digest passt nicht mehr */
        break;
    case F_TRUNCATED:
        *n -= 25;
        break;
    case F_NO_TOKEN: {
        static const uint8_t notok[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00};
        memcpy(resp, notok, sizeof(notok));
        *n = sizeof(notok);
        break;
    }
    case F_NO_EKU: {   /* TSTInfo der Test-TSA, signiert mit einem TSA-Zertifikat ohne EKU */
        exch_t x;
        memcpy(x.resp, resp, *n);
        x.resp_len = *n;
        uint8_t tok[4096];
        size_t tn = cms_token(&x, "tsa_noeku.pem", "tsa.key", tok, sizeof(tok));
        *n = wrap_resp(tok, tn, resp);
        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

typedef struct { const char *name; fault_t f; esp_err_t want; int offset; bool no_ca; } fault_case_t;

static void run_fault(const fault_case_t *fc, asics_tsa_mode_t mode)
{
    static const uint8_t data[] = "x;y\n";
    tsa_setup(mode);
    g_fault = fc->f;
    g_dev_offset = fc->offset;
    if (fc->no_ca) asics_tsa_host_set_ca_pem(NULL);
    asics_tsa_host_set_hook(fault_hook, NULL);
    sink_t s = {0};
    asics_sign_result_t res;
    esp_err_t e = asics_sign_ex("t.csv", data, sizeof(data) - 1, sink_write, &s, &res);
    char msg[96];
    snprintf(msg, sizeof(msg), "%s (%s)", fc->name, mode == ASICS_TSA_REQUIRED ? "REQUIRED" : "PREFERRED");
    if (mode == ASICS_TSA_REQUIRED) {
        TEST_ASSERT_EQUAL_HEX_MESSAGE(fc->want, e, msg);
        TEST_ASSERT_EQUAL_MESSAGE(0, s.calls, msg);          /* kein Container, kein Callback */
    } else {
        TEST_ASSERT_EQUAL_HEX_MESSAGE(ESP_OK, e, msg);
        TEST_ASSERT_EQUAL_MESSAGE(ASICS_LEVEL_B_B, res.level, msg);
        TEST_ASSERT_EQUAL_HEX_MESSAGE(fc->want, res.tsa_err, msg);
        TEST_ASSERT_TRUE_MESSAGE(s.calls > 0 && !contains(s.buf, s.len, OID_STS, sizeof(OID_STS)), msg);
    }
    asics_tsa_host_set_hook(NULL, NULL);
    sink_free(&s);
}

static void test_tsa_sign_faults(void)
{
    static const fault_case_t cases[] = {
        {"Transportfehler", F_TRANSPORT, ASICS_ERR_TSA_UNAVAILABLE, 0, false},
        {"Status rejected", F_REJECTED, ASICS_ERR_TSA_REJECTED, 0, false},
        {"falscher Imprint", F_IMPRINT, ASICS_ERR_TSA_INVALID, 0, false},
        {"falsche Nonce", F_NONCE, ASICS_ERR_TSA_INVALID, 0, false},
        {"manipulierte TSA-Signatur", F_SIGNATURE, ASICS_ERR_TSA_INVALID, 0, false},
        {"manipulierter TSTInfo", F_TSTINFO, ASICS_ERR_TSA_INVALID, 0, false},
        {"TSA-Zertifikat fremder CA", F_FOREIGN_CA, ASICS_ERR_TSA_INVALID, 0, false},
        {"TSA-Zertifikat ohne EKU", F_NO_EKU, ASICS_ERR_TSA_INVALID, 0, false},
        {"Antwort abgeschnitten", F_TRUNCATED, ASICS_ERR_TSA_INVALID, 0, false},
        {"Antwort zu gross", F_TOO_BIG, ASICS_ERR_TSA_INVALID, 0, false},
        {"Token fehlt", F_NO_TOKEN, ASICS_ERR_TSA_INVALID, 0, false},
        {"genTime ausserhalb Toleranz", F_CLOCK, ASICS_ERR_TSA_INVALID, 1000, false},
        {"keine TSA-CA eingebettet", F_CLOCK, ASICS_ERR_TSA_UNAVAILABLE, 0, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        run_fault(&cases[i], ASICS_TSA_PREFERRED);
        run_fault(&cases[i], ASICS_TSA_REQUIRED);
    }
}

/* OFF muss bytegleich zum bisherigen B-B sein: der deterministische Test (test_cades) deckt dies ab; hier
 * zusaetzlich: Modus-API und Default */
static void test_tsa_mode_api(void)
{
    /* Kconfig-Default PREFERRED: DEFAULT/NULL/nullinitialisiertes cfg behalten ihn, explizites OFF ueberschreibt */
    asics_host_set_tsa_default(ASICS_TSA_PREFERRED);
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());
    asics_config_t zero = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&zero));
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&(asics_config_t){.tsa_mode = ASICS_TSA_OFF}));
    TEST_ASSERT_EQUAL(ASICS_TSA_OFF, asics_get_tsa_mode());
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&zero));                 /* DEFAULT stellt den Default wieder her */
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());
    /* Setter */
    TEST_ASSERT_EQUAL(ESP_OK, asics_set_tsa_mode(ASICS_TSA_REQUIRED));
    TEST_ASSERT_EQUAL(ASICS_TSA_REQUIRED, asics_get_tsa_mode());
    TEST_ASSERT_EQUAL(ESP_OK, asics_set_tsa_mode(ASICS_TSA_DEFAULT));
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_set_tsa_mode((asics_tsa_mode_t)99));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_set_tsa_mode((asics_tsa_mode_t)-1));
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());        /* unveraendert */
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_signer_init(&(asics_config_t){.tsa_mode = (asics_tsa_mode_t)42}));
    TEST_ASSERT_EQUAL(ASICS_TSA_PREFERRED, asics_get_tsa_mode());
    /* Default REQUIRED / OFF */
    asics_host_set_tsa_default(ASICS_TSA_REQUIRED);
    TEST_ASSERT_EQUAL(ASICS_TSA_REQUIRED, asics_get_tsa_mode());
    asics_host_set_tsa_default(ASICS_TSA_OFF);
    TEST_ASSERT_EQUAL(ASICS_TSA_OFF, asics_get_tsa_mode());
}

/* ---- Externe TSA (tools/tsa/check.sh): Antwort aus Datei gegen die Anfrage der Komponente pruefen ---- */
static void test_tsa_external_response(void)
{
    const char *rq = getenv("ASICS_TSA_EXT_REQUEST"), *rs = getenv("ASICS_TSA_EXT_RESPONSE");
    if (!rq || !rs) {
        TEST_IGNORE_MESSAGE("ASICS_TSA_EXT_REQUEST/_RESPONSE nicht gesetzt (nur tools/tsa/check.sh)");
    }
    uint8_t req[256], resp[8192];
    FILE *f = fopen(rq, "rb");
    TEST_ASSERT_NOT_NULL(f);
    size_t rl = fread(req, 1, sizeof(req), f);
    fclose(f);
    f = fopen(rs, "rb");
    TEST_ASSERT_NOT_NULL(f);
    size_t n = fread(resp, 1, sizeof(resp), f);
    fclose(f);
    /* Digest und Nonce aus der Anfrage lesen: SEQ { INT 1, SEQ { SEQ alg, OCTET digest }, [OID], INT nonce, BOOL } */
    der_rd_t top = {req, req + rl}, r, mi, alg;
    uint8_t tag;
    const uint8_t *v, *digest, *nonce;
    size_t vl, nl;
    TEST_ASSERT_TRUE(der_rd_enter(&top, 0x30, &r) && der_rd_next(&r, &tag, &v, &vl, NULL, NULL));
    TEST_ASSERT_TRUE(der_rd_enter(&r, 0x30, &mi) && der_rd_enter(&mi, 0x30, &alg));
    TEST_ASSERT_TRUE(der_rd_next(&mi, &tag, &digest, &vl, NULL, NULL) && tag == 0x04 && vl == 32);
    if (der_rd_peek(&r) == 0x06) { TEST_ASSERT_TRUE(der_rd_next(&r, &tag, &v, &vl, NULL, NULL)); }
    TEST_ASSERT_TRUE(der_rd_next(&r, &tag, &nonce, &nl, NULL, NULL) && tag == 0x02);
    tsa_expect_t e = {.digest = digest, .nonce = nonce, .nonce_len = nl, .now = time(NULL), .tolerance_s = 300};
    tsa_resp_t pr;
    tsa_token_t t;
    time_t gt;
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_response(resp, n, &pr));
    TEST_ASSERT_EQUAL(ESP_OK, tsa_parse_token(pr.token, pr.token_len, &t));
    TEST_ASSERT_EQUAL(ESP_OK, tsa_check_tstinfo(t.tstinfo, t.tstinfo_len, &e, &gt));
    size_t cl;
    uint8_t *ca = test_pem_to_der("tsa_root.pem", &cl);
    esp_err_t err = tsa_verify_token(&t, ca, cl, gt);
    free(ca);
    TEST_ASSERT_EQUAL(ESP_OK, err);
}

/* Sektionsname und Pfad gehen nie durch eine Shell: ungueltige Namen fallen auf tsa_good zurueck, Sonderzeichen
 * fuehren nicht zu Kommandoausfuehrung */
static void test_tsa_host_safe_args(void)
{
    uint8_t digest[32] = {1}, nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8}, req[128], resp[4096];
    size_t rl, n;
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_build_request(digest, nonce, NULL, req, sizeof(req), &rl));
    asics_tsa_host_set_hook(NULL, NULL);
    const char *marker = "/tmp/asics_tsa_injected";
    remove(marker);
    asics_tsa_host_set_section("tsa_good; touch /tmp/asics_tsa_injected #");
    TEST_ASSERT_EQUAL(ESP_OK, asics_tsa_transport(req, rl, resp, sizeof(resp), &n));   /* Standard-Sektion */
    FILE *f = fopen(marker, "r");
    TEST_ASSERT_NULL(f);
    asics_tsa_host_set_section("gibt_es_nicht");                                        /* gueltiger Name, Sektion fehlt */
    TEST_ASSERT_EQUAL(ASICS_ERR_TSA_UNAVAILABLE, asics_tsa_transport(req, rl, resp, sizeof(resp), &n));
    asics_tsa_host_set_section("tsa_good");
}

void run_tsa_tests(void)
{
    RUN_TEST(test_tsa_request_vectors);
    RUN_TEST(test_tsa_request_errors);
    RUN_TEST(test_tsa_host_transport);
    RUN_TEST(test_tsa_host_safe_args);
    RUN_TEST(test_tsa_resp_good);
    RUN_TEST(test_tsa_resp_bad_structure);
    RUN_TEST(test_tsa_generalized_time);
    RUN_TEST(test_tsa_verify_good);
    RUN_TEST(test_tsa_verify_negative);
    RUN_TEST(test_tsa_verify_certificates);
    RUN_TEST(test_tsa_sign_modes_ok);
    RUN_TEST(test_tsa_sign_faults);
    RUN_TEST(test_tsa_mode_api);
    RUN_TEST(test_tsa_external_response);
}
