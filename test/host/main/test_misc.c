/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <string.h>
#include <stdlib.h>
#include "test_support.h"
#include "asics_signer.h"
#include "asics_provision.h"
#include "kv_store.h"
#include "pem_util.h"
#include "mbedtls/base64.h"
#include "time_source.h"

static time_t g_now = TEST_TIME;
static time_t now_fn(void) { return g_now; }

static void setup(void)
{
    g_now = TEST_TIME;
    asics_time_set_provider(now_fn);
    test_install_device_key();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));
}

static esp_err_t never(const void *b, size_t l, void *c) { (void)b; (void)l; (*(int *)c)++; return ESP_OK; }

static void test_time_check(void)
{
    setup();
    test_load_certs("dev.pem", "ca.pem");
    int calls = 0;
    g_now = asics_time_min() - 1;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(0, calls);                      /* keine Signatur, keine Ausgabe */
    g_now = asics_time_min();                         /* Zeit akzeptiert; Test-Zertifikat gilt erst ab 2024 */
    TEST_ASSERT_EQUAL(ASICS_ERR_SIGNER_CERT_VALIDITY, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    g_now = TEST_TIME;
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_TRUE(calls > 0);
    time_t t;
    g_now = (time_t)-1;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_time_get(&t));
}

/* Signierzeit nach 2107 passt nicht in den ZIP-DOS-Zeitstempel: vor dem Signieren abgelehnt */
static void test_sign_time_range(void)
{
    setup();
    test_load_certs("dev.pem", "ca.pem");
    int calls = 0;
    g_now = (time_t)4354819200LL;                    /* 2108-01-01 */
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    g_now = (time_t)253402300800LL;                  /* Jahr 10000 */
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(0, calls);
}

static void test_state_machine(void)
{
    g_now = TEST_TIME;
    asics_time_set_provider(now_fn);
    asics_kv_ram_reset();
    TEST_ASSERT_EQUAL(ASICS_STATE_NO_KEY, asics_signer_get_state());
    int calls = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));            /* Zero-Touch: Schluessel entsteht */
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(0, calls);
}

static esp_err_t import_files(const char *dev, const char *ca)
{
    const char *c[1] = {ca};
    return test_import_chain(dev, c, 1);
}

static void test_import_checks(void)
{
    setup();
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_KEY_MISMATCH, import_files("other.pem", "ca.pem"));
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, import_files("dev.pem", "other.pem"));  /* kein CA-Flag / falscher Aussteller */
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, import_files("dev.pem", "dev.pem"));
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, import_files("dev.pem", "leaf_ca.pem"));
    uint8_t junk[50] = {0};
    size_t cl; uint8_t *c = test_pem_to_der("ca.pem", &cl);
    asics_der_t cd = {c, cl};
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_PARSE, asics_provision_import_der(junk, sizeof(junk), &cd, 1));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_provision_import_der(junk, sizeof(junk), &cd, 0));
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());           /* nichts gespeichert */
    g_now = (time_t)2398291200LL;                   /* 2045-12-31: ausserhalb der Gueltigkeit (bis 2044) */
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_VALIDITY, import_files("dev.pem", "ca.pem"));
    g_now = (time_t)1701000000;                     /* 2023-11-26: >= Mindestzeit, vor notBefore (2024) */
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_VALIDITY, import_files("dev.pem", "ca.pem"));
    g_now = TEST_TIME;
    TEST_ASSERT_EQUAL(ESP_OK, import_files("dev.pem", "ca.pem"));
    TEST_ASSERT_EQUAL(ASICS_STATE_PROVISIONED, asics_signer_get_state());
    free(c);
}

/* Uhr ungueltig: nur die Zeitpruefung entfaellt, Schluessel- und Kettenpruefung bleiben */
static void test_import_without_clock(void)
{
    setup();
    g_now = asics_time_min() - 5;
    TEST_ASSERT_EQUAL(ESP_OK, import_files("dev.pem", "ca.pem"));
    TEST_ASSERT_EQUAL(ASICS_STATE_PROVISIONED, asics_signer_get_state());
    setup();                                        /* frischer Speicher mit Fixture-Schluessel */
    g_now = asics_time_min() - 5;
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_KEY_MISMATCH, import_files("other.pem", "ca.pem"));
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, import_files("dev.pem", "other.pem"));
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, import_files("dev.pem", "leaf_ca.pem"));
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());
    /* Signieren bleibt ohne gueltige Uhr verweigert */
    setup();
    TEST_ASSERT_EQUAL(ESP_OK, import_files("dev.pem", "ca.pem"));
    g_now = asics_time_min() - 5;
    int calls = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(0, calls);
}

static void test_chain_lengths(void)
{
    setup();
    /* Laenge 2: Geraet + 1 CA (flach) */
    TEST_ASSERT_EQUAL(ESP_OK, import_files("dev.pem", "ca.pem"));
    /* Laenge 3: Geraet + Issuing + Intermediate (ohne Root, Teilkette) */
    const char *c3[] = {"issuing.pem", "inter.pem"};
    TEST_ASSERT_EQUAL(ESP_OK, test_import_chain("dev_chain.pem", c3, 2));
    /* Laenge 4: mit Root */
    const char *c4[] = {"issuing.pem", "inter.pem", "root.pem"};
    TEST_ASSERT_EQUAL(ESP_OK, test_import_chain("dev_chain.pem", c4, 3));
    /* nur Issuing (nicht selbstsigniert): Teilkette akzeptiert */
    const char *c1[] = {"issuing.pem"};
    TEST_ASSERT_EQUAL(ESP_OK, test_import_chain("dev_chain.pem", c1, 1));
    int calls = 0;
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
}

static void test_chain_errors(void)
{
    setup();
    /* falsche Reihenfolge */
    const char *wrong[] = {"inter.pem", "issuing.pem", "root.pem"};
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, test_import_chain("dev_chain.pem", wrong, 3));
    /* fehlendes Glied (Intermediate fehlt) */
    const char *gap[] = {"issuing.pem", "root.pem"};
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, test_import_chain("dev_chain.pem", gap, 2));
    /* Geraet gegen falsche Kette */
    const char *other[] = {"ca.pem", "root.pem"};
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, test_import_chain("dev_chain.pem", other, 2));
    /* Geraetezertifikat der Kette von anderer CA als im Bundle: ok-Fall zur Gegenprobe */
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());
    /* Maximum: Geraet + 4 CAs = 5 > CONFIG_ASICS_MAX_CHAIN (4) */
    TEST_ASSERT_EQUAL(4, CONFIG_ASICS_MAX_CHAIN);
    const char *many[] = {"issuing.pem", "inter.pem", "root.pem", "ca.pem"};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, test_import_chain("dev_chain.pem", many, 4));
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());
    /* Gueltigkeit eines Kettenglieds wird mitgeprueft */
    g_now = (time_t)2398291200LL;
    const char *ok[] = {"issuing.pem", "inter.pem", "root.pem"};
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_VALIDITY, test_import_chain("dev_chain.pem", ok, 3));
}

static void test_import_pem_bundle(void)
{
    setup();
    size_t dl, a, b, c;
    uint8_t *d = test_read_pki("dev_chain.pem", &dl);
    uint8_t *i = test_read_pki("issuing.pem", &a), *m = test_read_pki("inter.pem", &b), *r = test_read_pki("root.pem", &c);
    char *bundle = malloc(a + b + c + 4);
    memcpy(bundle, i, a); memcpy(bundle + a, m, b); memcpy(bundle + a + b, r, c); bundle[a + b + c] = 0;
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_import_pem((char *)d, bundle));
    TEST_ASSERT_EQUAL(ASICS_STATE_PROVISIONED, asics_signer_get_state());
    /* falsche Reihenfolge im Bundle */
    asics_kv_ram_reset();
    TEST_ASSERT_EQUAL(ESP_OK, asics_signer_init(NULL));
    test_install_device_key();
    memcpy(bundle, m, b); memcpy(bundle + b, i, a);
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_CHAIN, asics_provision_import_pem((char *)d, bundle));
    /* zu viele Bloecke */
    size_t e;
    uint8_t *x = test_read_pki("ca.pem", &e);
    char *big = malloc(a + b + c + e + 4);
    memcpy(big, i, a); memcpy(big + a, m, b); memcpy(big + a + b, r, c); memcpy(big + a + b + c, x, e);
    big[a + b + c + e] = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, asics_provision_import_pem((char *)d, big));
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_PARSE, asics_provision_import_pem((char *)d, "kein bundle"));
    free(bundle); free(big); free(d); free(i); free(m); free(r); free(x);
}

/* Import mit langem Issuer-DN: der Probe-Build muss exakt entscheiden, ob asics_sign spaeter gelingt */
static void test_import_probe_size(void)
{
    setup();
    const char *lng[] = {"longca.pem", "ca.pem"};
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, test_import_chain("dev_longdn.pem", lng, 2));
    TEST_ASSERT_EQUAL(ASICS_STATE_KEY_NO_CERT, asics_signer_get_state());   /* nichts gespeichert */
    const char *med[] = {"medca.pem", "ca.pem"};
    TEST_ASSERT_EQUAL(ESP_OK, test_import_chain("dev_meddn.pem", med, 2));
    int calls = 0;
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));   /* akzeptiert => signierbar */
    TEST_ASSERT_TRUE(calls > 0);
}

/* Auch die CA-Zertifikate der Kette werden beim Signieren geprueft (nicht nur das Geraetezertifikat) */
static void test_sign_chain_validity(void)
{
    int calls = 0;
    /* abgelaufene CA: Import zu TEST_TIME ok, Signieren nach Ablauf (2026-07-01) verweigert */
    setup();
    const char *sc[] = {"shortca.pem", "ca.pem"};
    TEST_ASSERT_EQUAL(ESP_OK, test_import_chain("dev_shortca.pem", sc, 2));
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    int ok_calls = calls;
    g_now = (time_t)1782864000LL;
    TEST_ASSERT_EQUAL(ASICS_ERR_SIGNER_CERT_VALIDITY, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(ok_calls, calls);

    /* noch nicht gueltige CA: Import ohne Uhr (keine Zeitpruefung) ok, Signieren vor 2026-03-01 verweigert */
    setup();
    g_now = asics_time_min() - 5;
    const char *fc[] = {"futureca.pem", "ca.pem"};
    TEST_ASSERT_EQUAL(ESP_OK, test_import_chain("dev_futureca.pem", fc, 2));
    g_now = TEST_TIME;                                   /* 2026-01-15 */
    calls = 0;
    TEST_ASSERT_EQUAL(ASICS_ERR_SIGNER_CERT_VALIDITY, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(0, calls);
    g_now = (time_t)1775001600LL;                        /* 2026-04-01 */
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
}

static void test_sign_cert_validity(void)
{
    setup();
    TEST_ASSERT_EQUAL(ESP_OK, import_files("dev.pem", "ca.pem"));
    int calls = 0;
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));   /* gueltig */
    int ok_calls = calls;
    g_now = (time_t)2398291200LL;                     /* abgelaufen (2044 Ende) */
    TEST_ASSERT_EQUAL(ASICS_ERR_SIGNER_CERT_VALIDITY, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    g_now = (time_t)1701000000;                       /* noch nicht gueltig, aber >= Mindestzeit */
    TEST_ASSERT_EQUAL(ASICS_ERR_SIGNER_CERT_VALIDITY, asics_sign("a.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(ok_calls, calls);               /* keine Ausgabe bei Verweigerung */
}

/* Erwartetes PEM unabhaengig mit mbedtls-Base64 bilden */
static void expected_pem(const char *label, const uint8_t *der, size_t len, char *out, size_t cap)
{
    size_t bl = 0;
    char *b64 = malloc(len * 2 + 8);
    TEST_ASSERT_EQUAL(0, mbedtls_base64_encode((unsigned char *)b64, len * 2 + 8, &bl, der, len));
    size_t n = (size_t)snprintf(out, cap, "-----BEGIN %s-----\n", label);
    for (size_t i = 0; i < bl; i += 64) {
        size_t c = bl - i > 64 ? 64 : bl - i;
        memcpy(out + n, b64 + i, c);
        n += c;
        out[n++] = '\n';
    }
    snprintf(out + n, cap - n, "-----END %s-----\n", label);
    free(b64);
}

/* Puffer exakt in Mindestgroesse: Ergebnis muss dem unabhaengig kodierten PEM entsprechen */
static void test_pem_encode_exact_buffer(void)
{
    const size_t lens[] = {1, 2, 3, 4, 47, 48, 49, 95, 96, 97, 144, 192, 300, 480, 481, 768, 1000};
    uint8_t der[1024];
    for (size_t i = 0; i < sizeof(der); i++) der[i] = (uint8_t)(i * 31 + 7);
    for (size_t k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        for (int l = 0; l < 2; l++) {
            const char *label = l ? "CERTIFICATE REQUEST" : "CERTIFICATE";
            size_t need = asics_pem_encoded_min_size(label, lens[k]);
            char *out = malloc(need), *want = malloc(need + 2048);
            size_t n = 0;
            TEST_ASSERT_EQUAL_MESSAGE(ESP_OK, asics_pem_encode(label, der, lens[k], out, need, &n), "Puffer == Mindestgroesse");
            expected_pem(label, der, lens[k], want, need + 2048);
            TEST_ASSERT_EQUAL(strlen(want), n);
            TEST_ASSERT_EQUAL_MEMORY(want, out, n);
            TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, asics_pem_encode(label, der, lens[k], out, need - 1, &n));
            free(out); free(want);
        }
    }
}

static void test_pem(void)
{
    uint8_t der[200];
    for (size_t i = 0; i < sizeof(der); i++) der[i] = (uint8_t)(i * 13);
    for (size_t n = 0; n <= sizeof(der); n += 37) {
        char pem[600]; size_t pl, dl; uint8_t back[200];
        TEST_ASSERT_EQUAL(ESP_OK, asics_pem_encode("CERTIFICATE", der, n, pem, sizeof(pem), &pl));
        TEST_ASSERT_EQUAL(strlen(pem), pl);
        if (n) {
            TEST_ASSERT_EQUAL(ESP_OK, asics_pem_decode("CERTIFICATE", pem, pl, back, sizeof(back), &dl));
            TEST_ASSERT_EQUAL(n, dl);
            TEST_ASSERT_EQUAL_MEMORY(der, back, n);
        }
    }
    char small[50]; size_t pl;
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, asics_pem_encode("CERTIFICATE", der, 100, small, sizeof(small), &pl));

    /* zeilenweiser Leser */
    char buf[400];
    asics_pem_reader_t r;
    asics_pem_reader_init(&r, buf, sizeof(buf), "CERTIFICATE");
    TEST_ASSERT_EQUAL(ASICS_PEM_NEED_MORE, asics_pem_reader_feed(&r, "Rauschen\r\n"));
    TEST_ASSERT_EQUAL(ASICS_PEM_NEED_MORE, asics_pem_reader_feed(&r, "-----BEGIN CERTIFICATE-----\r\n"));
    TEST_ASSERT_EQUAL(ASICS_PEM_NEED_MORE, asics_pem_reader_feed(&r, "AAAA\n"));
    TEST_ASSERT_EQUAL(ASICS_PEM_DONE, asics_pem_reader_feed(&r, "-----END CERTIFICATE-----\n"));
    uint8_t out[8]; size_t ol;
    TEST_ASSERT_EQUAL(ESP_OK, asics_pem_decode("CERTIFICATE", buf, r.len, out, sizeof(out), &ol));
    TEST_ASSERT_EQUAL(3, ol);
    asics_pem_reader_init(&r, buf, 40, "CERTIFICATE");
    asics_pem_reader_feed(&r, "-----BEGIN CERTIFICATE-----");
    TEST_ASSERT_EQUAL(ASICS_PEM_ERROR, asics_pem_reader_feed(&r, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="));
}

static void test_import_pem_api(void)
{
    setup();
    size_t dl, cl;
    uint8_t *pd = test_read_pki("dev.pem", &dl), *pc = test_read_pki("ca.pem", &cl);
    TEST_ASSERT_EQUAL(ESP_OK, asics_provision_import_pem((char *)pd, (char *)pc));
    TEST_ASSERT_EQUAL(ASICS_STATE_PROVISIONED, asics_signer_get_state());
    TEST_ASSERT_EQUAL(ASICS_ERR_CERT_PARSE, asics_provision_import_pem("kein pem", (char *)pc));
    free(pd); free(pc);
}

static void test_sign_args(void)
{
    setup();
    test_load_certs("dev.pem", "ca.pem");
    int calls = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_sign("dir/x.csv", (const uint8_t *)"x", 1, never, &calls));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_sign("x.csv", NULL, 5, never, &calls));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, asics_sign("x.csv", (const uint8_t *)"x", 1, NULL, NULL));
    TEST_ASSERT_EQUAL(0, calls);
    TEST_ASSERT_EQUAL(ESP_OK, asics_sign("x.csv", NULL, 0, never, &calls));
}

void run_misc_tests(void)
{
    RUN_TEST(test_time_check);
    RUN_TEST(test_sign_time_range);
    RUN_TEST(test_state_machine);
    RUN_TEST(test_import_checks);
    RUN_TEST(test_import_without_clock);
    RUN_TEST(test_chain_lengths);
    RUN_TEST(test_chain_errors);
    RUN_TEST(test_import_probe_size);
    RUN_TEST(test_import_pem_bundle);
    RUN_TEST(test_sign_cert_validity);
    RUN_TEST(test_sign_chain_validity);
    RUN_TEST(test_pem);
    RUN_TEST(test_pem_encode_exact_buffer);
    RUN_TEST(test_import_pem_api);
    RUN_TEST(test_sign_args);
}
