#include <string.h>
#include <stdlib.h>
#include "test_support.h"
#include "asics_container.h"
#include "zip_writer.h"

static uint32_t crc_ref(const uint8_t *d, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & -(c & 1));
    }
    return ~c;
}
static uint16_t g16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static uint32_t g32(const uint8_t *p) { return g16(p) | ((uint32_t)g16(p + 2) << 16); }

static const uint8_t SIG[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

static void check_layout(const sink_t *s, const char *name, const uint8_t *pl, size_t plen)
{
    const uint8_t *z = s->buf;
    const char *names[3] = {"mimetype", name, "META-INF/signature.p7s"};
    const uint8_t *data[3] = {(const uint8_t *)"application/vnd.etsi.asic-s+zip", pl, SIG};
    size_t lens[3] = {31, plen, sizeof(SIG)};
    uint32_t off[3];
    size_t pos = 0;
    for (int i = 0; i < 3; i++) {
        off[i] = pos;
        TEST_ASSERT_EQUAL_HEX32(0x04034b50, g32(z + pos));
        TEST_ASSERT_EQUAL(0, g16(z + pos + 6));            /* keine Flags (ASCII) */
        TEST_ASSERT_EQUAL(0, g16(z + pos + 8));            /* STORE */
        TEST_ASSERT_EQUAL_HEX32(crc_ref(data[i], lens[i]), g32(z + pos + 14));
        TEST_ASSERT_EQUAL(lens[i], g32(z + pos + 18));
        TEST_ASSERT_EQUAL(lens[i], g32(z + pos + 22));
        TEST_ASSERT_EQUAL(strlen(names[i]), g16(z + pos + 26));
        TEST_ASSERT_EQUAL(0, g16(z + pos + 28));           /* kein Extra-Feld */
        TEST_ASSERT_EQUAL_MEMORY(names[i], z + pos + 30, strlen(names[i]));
        pos += 30 + strlen(names[i]);
        if (lens[i]) TEST_ASSERT_EQUAL_MEMORY(data[i], z + pos, lens[i]);
        pos += lens[i];
    }
    /* mimetype-Inhalt ab Offset 38, Name an Offset 30 */
    TEST_ASSERT_EQUAL_MEMORY("mimetype", z + 30, 8);
    TEST_ASSERT_EQUAL_MEMORY("application/vnd.etsi.asic-s+zip", z + 38, 31);
    /* Central Directory */
    uint32_t cd = pos;
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_HEX32(0x02014b50, g32(z + pos));
        TEST_ASSERT_EQUAL_HEX32(crc_ref(data[i], lens[i]), g32(z + pos + 16));
        TEST_ASSERT_EQUAL(off[i], g32(z + pos + 42));
        pos += 46 + strlen(names[i]);
    }
    TEST_ASSERT_EQUAL_HEX32(0x06054b50, g32(z + pos));
    TEST_ASSERT_EQUAL(3, g16(z + pos + 10));
    TEST_ASSERT_EQUAL(pos - cd, g32(z + pos + 12));
    TEST_ASSERT_EQUAL(cd, g32(z + pos + 16));
    TEST_ASSERT_EQUAL(pos + 22, s->len);
}

static void test_zip_layout(void)
{
    uint8_t pl[300];
    for (size_t i = 0; i < sizeof(pl); i++) pl[i] = (uint8_t)(i * 7 + 3);
    sink_t s = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_write("data.csv", pl, sizeof(pl), SIG, sizeof(SIG), TEST_TIME, sink_write, &s));
    check_layout(&s, "data.csv", pl, sizeof(pl));
    /* DOS-Zeit 2026-01-15 12:00:00 */
    TEST_ASSERT_EQUAL_HEX16((12 << 11), g16(s.buf + 10));
    TEST_ASSERT_EQUAL_HEX16(((2026 - 1980) << 9) | (1 << 5) | 15, g16(s.buf + 12));
    sink_free(&s);
}

static void test_zip_empty_and_large(void)
{
    sink_t s = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_write("e.csv", NULL, 0, SIG, sizeof(SIG), TEST_TIME, sink_write, &s));
    check_layout(&s, "e.csv", (const uint8_t *)"", 0);
    sink_free(&s);

    size_t n = 100000;
    uint8_t *pl = malloc(n);
    for (size_t i = 0; i < n; i++) pl[i] = (uint8_t)(i ^ (i >> 8));
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_write("big.csv", pl, n, SIG, sizeof(SIG), TEST_TIME, sink_write, &s));
    check_layout(&s, "big.csv", pl, n);
    TEST_ASSERT_TRUE(s.calls > 100000 / CONFIG_ASICS_WRITE_CHUNK); /* gechunkt */
    free(pl);
    sink_free(&s);
}

static void test_zip_callback_error(void)
{
    uint8_t pl[100] = {1};
    sink_t probe = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_write("d.csv", pl, sizeof(pl), SIG, sizeof(SIG), TEST_TIME, sink_write, &probe));
    int total = probe.calls;
    sink_free(&probe);
    for (int f = 1; f <= total; f++) {
        sink_t s = {.fail_at = f};
        esp_err_t e = asics_container_write("d.csv", pl, sizeof(pl), SIG, sizeof(SIG), TEST_TIME, sink_write, &s);
        TEST_ASSERT_EQUAL_MESSAGE(ESP_ERR_INVALID_RESPONSE, e, "Callback-Fehler muss durchgereicht werden");
        TEST_ASSERT_EQUAL_MESSAGE(f, s.calls, "nach dem Fehler keine weiteren Callbacks");
        sink_free(&s);
    }
}

static void test_zip_names(void)
{
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_check_name("a.csv"));
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_check_name("Messung 2026-01.csv"));
    const char *bad[] = {"", ".hidden", "dir/a.csv", "a\\b", "mimetype", "META-INF", "META-INF/x", "a\nb", NULL};
    for (int i = 0; bad[i]; i++) TEST_ASSERT_NOT_EQUAL_MESSAGE(ESP_OK, asics_container_check_name(bad[i]), bad[i]);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, asics_container_check_name(NULL));
    char longn[300];
    memset(longn, 'a', sizeof(longn)); longn[299] = 0;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, asics_container_check_name(longn));
}

static void test_zip_utf8_flag(void)
{
    sink_t s = {0};
    TEST_ASSERT_EQUAL(ESP_OK, asics_container_write("M\xc3\xbc" "ll.csv", (const uint8_t *)"x", 1, SIG, sizeof(SIG), TEST_TIME, sink_write, &s));
    size_t first = 30 + 8 + 31;
    TEST_ASSERT_EQUAL_HEX16(0x0800, g16(s.buf + first + 6));
    sink_free(&s);
}

static void test_zip_dos_time(void)
{
    uint16_t t, d;
    TEST_ASSERT_EQUAL(ESP_OK, zip_dos_time(315532800 /* 1980-01-01 */, &t, &d));
    TEST_ASSERT_EQUAL_HEX16(0x0021, d);
    TEST_ASSERT_EQUAL(0, t);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, zip_dos_time(0, &t, &d));
}

void run_zip_tests(void)
{
    RUN_TEST(test_zip_layout);
    RUN_TEST(test_zip_empty_and_large);
    RUN_TEST(test_zip_callback_error);
    RUN_TEST(test_zip_names);
    RUN_TEST(test_zip_utf8_flag);
    RUN_TEST(test_zip_dos_time);
}
