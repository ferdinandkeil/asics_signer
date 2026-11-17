/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_support.h"
#include "asics_signer.h"
#include "asics_provision.h"
#include "cades_builder.h"
#include "time_source.h"
#include "kv_store.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

static time_t fixed_time(void) { return TEST_TIME; }

/* --- minimaler DER-Walker --- */
typedef struct { const uint8_t *p, *end; } cur_t;
static const uint8_t *next(cur_t *c, uint8_t *tag, size_t *len)
{
    TEST_ASSERT_TRUE(c->p + 2 <= c->end);
    *tag = *c->p++;
    size_t l = *c->p++;
    if (l & 0x80) {
        int n = l & 0x7f;
        l = 0;
        while (n--) l = (l << 8) | *c->p++;
    }
    TEST_ASSERT_TRUE(c->p + l <= c->end);
    const uint8_t *v = c->p;
    *len = l;
    c->p += l;
    return v;
}
static cur_t enter(cur_t *c, uint8_t want)
{
    uint8_t t; size_t l;
    const uint8_t *v = next(c, &t, &l);
    TEST_ASSERT_EQUAL_HEX8(want, t);
    return (cur_t){v, v + l};
}

/* Stub-Signierer: fester ECDSA-artiger Wert -> deterministische Ausgabe */
static esp_err_t stub_sign(const uint8_t d[32], uint8_t *sig, size_t sz, size_t *sl, void *ctx)
{
    static const uint8_t s[] = {0x30, 0x06, 0x02, 0x01, 0x11, 0x02, 0x01, 0x22};
    (void)d; (void)sz; (void)ctx;
    memcpy(sig, s, sizeof(s));
    *sl = sizeof(s);
    return ESP_OK;
}

static esp_err_t hook(der_t *d, const uint8_t *sig, size_t sl, void *ctx)
{
    (void)sig; (void)sl; (void)ctx;
    static const uint8_t oid[] = {0x2A, 0x03};
    size_t m = der_size(d);
    size_t m2 = der_size(d);
    der_int(d, 5);
    der_wrap(d, m2, 0x31);
    der_oid(d, oid, sizeof(oid));
    der_wrap(d, m, 0x30);
    return ESP_OK;
}

static uint8_t cms[CONFIG_ASICS_CMS_BUF_SIZE];

static esp_err_t hook_empty(der_t *d, const uint8_t *sig, size_t sl, void *ctx)
{
    (void)d; (void)sig; (void)sl; (void)ctx;
    return ESP_OK;                                   /* schreibt nichts */
}
static bool g_empty_hook;

static size_t build(time_t t, bool with_hook)
{
    size_t dl, cl, n;
    uint8_t *dev = test_pem_to_der("dev.pem", &dl), *ca = test_pem_to_der("ca.pem", &cl);
    asics_der_t cad = {ca, cl};
    cades_params_t p = {.signing_time = t, .dev_cert = dev, .dev_cert_len = dl, .ca_certs = &cad, .ca_count = 1,
                        .sign = stub_sign};
    memset(p.payload_digest, 0xAB, 32);
    if (with_hook) p.unsigned_attrs = g_empty_hook ? hook_empty : hook;
    TEST_ASSERT_EQUAL(ESP_OK, cades_build(&p, cms, sizeof(cms), &n));
    free(dev); free(ca);
    return n;
}

/* Struktur parsen und Zeiger auf Signed Attributes (inkl. Header) liefern */
typedef struct { int ncerts; const uint8_t *attrs; size_t attrs_len; cur_t si_rest; const uint8_t *sig; size_t sig_len; } parsed_t;

static parsed_t parse(size_t n)
{
    cur_t top = {cms, cms + n};
    cur_t ci = enter(&top, 0x30);
    TEST_ASSERT_TRUE(top.p == top.end);
    uint8_t t; size_t l;
    const uint8_t *v = next(&ci, &t, &l);                     /* OID signedData */
    TEST_ASSERT_EQUAL_HEX8(0x06, t);
    static const uint8_t sd[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02};
    TEST_ASSERT_EQUAL(sizeof(sd), l);
    TEST_ASSERT_EQUAL_MEMORY(sd, v, l);
    cur_t ex = enter(&ci, 0xA0);
    cur_t s = enter(&ex, 0x30);
    next(&s, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x02, t); TEST_ASSERT_EQUAL(1, l);   /* version 1 */
    cur_t da = enter(&s, 0x31);
    (void)da;
    cur_t eci = enter(&s, 0x30);                               /* encapContentInfo ohne eContent */
    next(&eci, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x06, t);
    TEST_ASSERT_TRUE(eci.p == eci.end);
    cur_t certs = enter(&s, 0xA0);
    int ncerts = 0;
    const uint8_t *prev_c = NULL; size_t prev_cl = 0;
    while (certs.p < certs.end) {          /* Zertifikate DER-sortiert (SET OF) */
        const uint8_t *st = certs.p;
        next(&certs, &t, &l);
        TEST_ASSERT_EQUAL_HEX8(0x30, t);
        size_t tot = (size_t)(certs.p - st);
        if (prev_c) { TEST_ASSERT_TRUE(memcmp(prev_c, st, tot < prev_cl ? tot : prev_cl) <= 0); }
        prev_c = st; prev_cl = tot;
        ncerts++;
    }
    cur_t sis = enter(&s, 0x31);
    TEST_ASSERT_TRUE(s.p == s.end);
    cur_t si = enter(&sis, 0x30);
    TEST_ASSERT_TRUE(sis.p == sis.end);
    next(&si, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x02, t); TEST_ASSERT_EQUAL(1, l);   /* SignerInfo v1 */
    next(&si, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x30, t);                           /* issuerAndSerial */
    next(&si, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x30, t);                           /* digestAlg */
    parsed_t r = {0};
    r.ncerts = ncerts;
    r.attrs = si.p;
    next(&si, &t, &l);
    TEST_ASSERT_EQUAL_HEX8(0xA0, t);
    r.attrs_len = (size_t)(si.p - r.attrs);
    next(&si, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x30, t);                           /* sigAlg */
    r.sig = next(&si, &t, &l); TEST_ASSERT_EQUAL_HEX8(0x04, t);
    r.sig_len = l;
    r.si_rest = si;
    return r;
}

static void test_cades_structure_and_determinism(void)
{
    size_t n1 = build(TEST_TIME, false);
    uint8_t copy[CONFIG_ASICS_CMS_BUF_SIZE];
    memcpy(copy, cms, n1);
    size_t n2 = build(TEST_TIME, false);
    TEST_ASSERT_EQUAL(n1, n2);
    TEST_ASSERT_EQUAL_MEMORY(copy, cms, n1);               /* deterministisch */

    parsed_t r = parse(n2);
    TEST_ASSERT_TRUE(r.si_rest.p == r.si_rest.end);        /* kein unsignedAttrs */
    TEST_ASSERT_EQUAL(8, r.sig_len);
    TEST_ASSERT_EQUAL(2, r.ncerts);

    /* Attribute: genau 4, Typen vollstaendig, DER-sortiert (aufsteigend) */
    cur_t a = {r.attrs, r.attrs + r.attrs_len};
    cur_t set = enter(&a, 0xA0);
    const uint8_t *prev = NULL; size_t prevlen = 0;
    int cnt = 0;
    bool seen[4] = {0};
    while (set.p < set.end) {
        const uint8_t *start = set.p;
        uint8_t t; size_t l;
        const uint8_t *v = next(&set, &t, &l);
        TEST_ASSERT_EQUAL_HEX8(0x30, t);
        size_t total = (size_t)(set.p - start);
        if (prev) {
            size_t m = total < prevlen ? total : prevlen;
            TEST_ASSERT_TRUE_MESSAGE(memcmp(prev, start, m) <= 0, "Attribute nicht DER-sortiert");
        }
        prev = start; prevlen = total;
        cur_t at = {v, v + l};
        uint8_t ot; size_t ol;
        const uint8_t *oid = next(&at, &ot, &ol);
        uint8_t last = oid[ol - 1];
        if (ol == 9 && last == 3) seen[0] = true;       /* content-type */
        if (ol == 9 && last == 4) seen[1] = true;       /* message-digest */
        if (ol == 9 && last == 5) seen[2] = true;       /* signing-time */
        if (ol == 11 && last == 0x2F) seen[3] = true;   /* signing-certificate-v2 */
        cnt++;
    }
    TEST_ASSERT_EQUAL(4, cnt);
    for (int i = 0; i < 4; i++) TEST_ASSERT_TRUE(seen[i]);
}

static void test_cades_time_encoding(void)
{
    size_t n = build(TEST_TIME, false);
    /* UTCTime "260115120000Z" */
    static const uint8_t u[] = {0x17, 0x0D, '2','6','0','1','1','5','1','2','0','0','0','0','Z'};
    bool found = false;
    for (size_t i = 0; i + sizeof(u) <= n; i++) if (!memcmp(cms + i, u, sizeof(u))) found = true;
    TEST_ASSERT_TRUE(found);

    n = build((time_t)2524608000LL + 3661, false);  /* 2050-01-01 01:01:01 -> GeneralizedTime */
    static const uint8_t g[] = {0x18, 0x0F, '2','0','5','0','0','1','0','1','0','1','0','1','0','1','Z'};
    found = false;
    for (size_t i = 0; i + sizeof(g) <= n; i++) if (!memcmp(cms + i, g, sizeof(g))) found = true;
    TEST_ASSERT_TRUE(found);
    n = build((time_t)2524608000LL - 1, false);     /* 2049-12-31 23:59:59 -> noch UTCTime */
    static const uint8_t e[] = {0x17, 0x0D, '4','9','1','2','3','1','2','3','5','9','5','9','Z'};
    found = false;
    for (size_t i = 0; i + sizeof(e) <= n; i++) if (!memcmp(cms + i, e, sizeof(e))) found = true;
    TEST_ASSERT_TRUE(found);
}

static void test_cades_time_range(void)
{
    size_t dl, cl, n;
    uint8_t *dev = test_pem_to_der("dev.pem", &dl), *ca = test_pem_to_der("ca.pem", &cl);
    asics_der_t cad = {ca, cl};
    cades_params_t p = {.dev_cert = dev, .dev_cert_len = dl, .ca_certs = &cad, .ca_count = 1, .sign = stub_sign};
    p.signing_time = (time_t)253402300799LL;   /* 9999-12-31 23:59:59: noch darstellbar */
    TEST_ASSERT_EQUAL(ESP_OK, cades_build(&p, cms, sizeof(cms), &n));
    p.signing_time = (time_t)253402300800LL;   /* Jahr 10000: kein abgeschnittener String, sondern Fehler */
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, cades_build(&p, cms, sizeof(cms), &n));
    p.signing_time = (time_t)-2208988800LL;    /* 1900 */
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, cades_build(&p, cms, sizeof(cms), &n));
    free(dev); free(ca);
}

static void test_cades_unsigned_hook(void)
{
    size_t n0 = build(TEST_TIME, false);
    size_t n = build(TEST_TIME, true);
    TEST_ASSERT_TRUE(n > n0);
    parsed_t r = parse(n);
    uint8_t t; size_t l;
    next(&r.si_rest, &t, &l);
    TEST_ASSERT_EQUAL_HEX8(0xA1, t);
    TEST_ASSERT_TRUE(r.si_rest.p == r.si_rest.end);
}

/* Hook ohne Ausgabe: kein leeres [1] (A1 00), Ergebnis identisch zum Fall ohne Hook */
static void test_cades_unsigned_hook_empty(void)
{
    size_t n0 = build(TEST_TIME, false);
    uint8_t copy[CONFIG_ASICS_CMS_BUF_SIZE];
    memcpy(copy, cms, n0);
    g_empty_hook = true;
    size_t n = build(TEST_TIME, true);
    g_empty_hook = false;
    TEST_ASSERT_EQUAL(n0, n);
    TEST_ASSERT_EQUAL_MEMORY(copy, cms, n);
    parsed_t r = parse(n);
    TEST_ASSERT_TRUE(r.si_rest.p == r.si_rest.end);
}

static void test_cades_buffer_too_small(void)
{
    size_t dl, cl, n;
    uint8_t *dev = test_pem_to_der("dev.pem", &dl), *ca = test_pem_to_der("ca.pem", &cl);
    asics_der_t cad = {ca, cl};
    cades_params_t p = {.signing_time = TEST_TIME, .dev_cert = dev, .dev_cert_len = dl, .ca_certs = &cad, .ca_count = 1, .sign = stub_sign};
    uint8_t small[200];
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, cades_build(&p, small, sizeof(small), &n));
    free(dev); free(ca);
}

/* End-to-End: echte Signatur pruefen (Signatur ueber 0x31||attrs mit Public Key des Gerätezertifikats) */
static void test_e2e_sign_and_verify(void)
{
    asics_time_set_provider(fixed_time);
    test_install_device_key();
    asics_config_t cfg = {.device_serial = "SN-1"};
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(&cfg));
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());
    test_load_certs("dev.pem", "ca.pem");
    TEST_ASSERT_EQUAL(ASICS_STATE_PROVISIONED, asics_signer_get_state());

    const char *csv = "zeit;wert\n2026-01-15T12:00:00Z;42,5\n";
    sink_t s = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("messung.csv", (const uint8_t *)csv, strlen(csv), sink_write, &s));
    test_write_out("messung.csv", csv, strlen(csv));
    test_write_out("sample.asics", s.buf, s.len);

    /* Signatur-Eintrag extrahieren (letzter Local Header) */
    size_t pos = 30 + 8 + 31;                                         /* nach mimetype */
    pos += 30 + 11 + strlen(csv);                                     /* nach messung.csv */
    const uint8_t *signame = s.buf + pos + 30;
    TEST_ASSERT_EQUAL_MEMORY("META-INF/signature.p7s", signame, 22);
    size_t sl = s.buf[pos + 18] | (s.buf[pos + 19] << 8) | (s.buf[pos + 20] << 16);
    memcpy(cms, s.buf + pos + 30 + 22, sl);
    parsed_t r = parse(sl);

    uint8_t *attrs = malloc(r.attrs_len);
    memcpy(attrs, r.attrs, r.attrs_len);
    attrs[0] = 0x31;
    uint8_t h[32];
    mbedtls_sha256(attrs, r.attrs_len, h, 0);
    free(attrs);
    size_t dl;
    uint8_t *dev = test_pem_to_der("dev.pem", &dl);
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    TEST_ASSERT_EQUAL(0, mbedtls_x509_crt_parse_der(&crt, dev, dl));
    TEST_ASSERT_EQUAL(0, mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, h, 32, r.sig, r.sig_len));
    mbedtls_x509_crt_free(&crt);
    free(dev);

    /* message-digest-Attribut == SHA-256 der Nutzdaten */
    uint8_t pd[32];
    mbedtls_sha256((const uint8_t *)csv, strlen(csv), pd, 0);
    bool found = false;
    for (size_t i = 0; i + 32 <= r.attrs_len; i++) if (!memcmp(r.attrs + i, pd, 32)) found = true;
    TEST_ASSERT_TRUE(found);
    sink_free(&s);
}

static void chain_sign(const char *const *chain, size_t n, int expect_certs, const char *outname)
{
    asics_time_set_provider(fixed_time);
    test_install_device_key();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));
    TEST_ASSERT_EQUAL_HEX(ESP_OK, test_import_chain("dev_chain.pem", chain, n));
    const char *csv = "zeit;wert\n2026-01-15T12:00:00Z;42,5\n";
    sink_t s = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("messung.csv", (const uint8_t *)csv, strlen(csv), sink_write, &s));
    size_t pos = 30 + 8 + 31 + 30 + 11 + strlen(csv);
    size_t sl = s.buf[pos + 18] | (s.buf[pos + 19] << 8) | (s.buf[pos + 20] << 16);
    TEST_ASSERT_TRUE(sl <= sizeof(cms));
    memcpy(cms, s.buf + pos + 30 + 22, sl);
    parsed_t r = parse(sl);
    TEST_ASSERT_EQUAL(expect_certs, r.ncerts);
    test_write_out(outname, s.buf, s.len);
    sink_free(&s);
}

static void test_chain_in_cms(void)
{
    const char *c4[] = {"issuing.pem", "inter.pem", "root.pem"};   /* Geraet + 3 CAs = 4 Zertifikate */
    chain_sign(c4, 3, 4, "sample_chain.asics");
    const char *c3[] = {"issuing.pem", "inter.pem"};               /* ohne Root */
    chain_sign(c3, 2, 3, "sample_chain3.asics");
}

void run_cades_tests(void)
{
    RUN_TEST(test_cades_structure_and_determinism);
    RUN_TEST(test_cades_time_encoding);
    RUN_TEST(test_cades_time_range);
    RUN_TEST(test_cades_unsigned_hook);
    RUN_TEST(test_cades_unsigned_hook_empty);
    RUN_TEST(test_cades_buffer_too_small);
    RUN_TEST(test_e2e_sign_and_verify);
    RUN_TEST(test_chain_in_cms);
}
