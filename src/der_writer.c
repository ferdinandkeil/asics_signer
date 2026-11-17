#include <string.h>
#include "der_writer.h"
#include "mbedtls/asn1write.h"

void der_init(der_t *d, uint8_t *buf, size_t size)
{
    d->start = buf;
    d->end = buf + size;
    d->p = buf + size;
    d->err = 0;
}

static void check(der_t *d, int rc)
{
    if (rc < 0) {
        d->err = rc;
    }
}

void der_raw(der_t *d, const uint8_t *data, size_t len)
{
    if (d->err) {
        return;
    }
    if ((size_t)(d->p - d->start) < len) {
        d->err = -1;
        return;
    }
    d->p -= len;
    if (len) {
        memcpy(d->p, data, len);
    }
}

void der_wrap(der_t *d, size_t mark, uint8_t tag)
{
    if (d->err) {
        return;
    }
    size_t content = der_size(d) - mark;
    check(d, mbedtls_asn1_write_len(&d->p, d->start, content));
    if (d->err) {
        return;
    }
    check(d, mbedtls_asn1_write_tag(&d->p, d->start, tag));
}

void der_oid(der_t *d, const uint8_t *oid, size_t len)
{
    if (d->err) {
        return;
    }
    check(d, mbedtls_asn1_write_oid(&d->p, d->start, (const char *)oid, len));
}

void der_int(der_t *d, int v)
{
    if (d->err) {
        return;
    }
    check(d, mbedtls_asn1_write_int(&d->p, d->start, v));
}

void der_int_raw(der_t *d, const uint8_t *content, size_t len)
{
    size_t mark = der_size(d);
    der_raw(d, content, len);
    der_wrap(d, mark, MBEDTLS_ASN1_INTEGER);
}

void der_octet_string(der_t *d, const uint8_t *data, size_t len)
{
    size_t mark = der_size(d);
    der_raw(d, data, len);
    der_wrap(d, mark, MBEDTLS_ASN1_OCTET_STRING);
}

void der_bit_string(der_t *d, const uint8_t *data, size_t len)
{
    size_t mark = der_size(d);
    der_raw(d, data, len);
    uint8_t unused = 0;
    der_raw(d, &unused, 1);
    der_wrap(d, mark, MBEDTLS_ASN1_BIT_STRING);
}

void der_string(der_t *d, uint8_t tag, const char *s, size_t len)
{
    size_t mark = der_size(d);
    der_raw(d, (const uint8_t *)s, len);
    der_wrap(d, mark, tag);
}

/* Oktettvergleich nach X.690 11.6 (kuerzere Folge gilt als mit Nullen aufgefuellt). */
static int item_cmp(const der_item_t *a, const der_item_t *b)
{
    size_t m = a->len < b->len ? a->len : b->len;
    int c = memcmp(a->p, b->p, m);
    if (c != 0) {
        return c;
    }
    const der_item_t *longer = a->len > b->len ? a : b;
    size_t lo = m, hi = longer->len;
    for (size_t i = lo; i < hi; i++) {
        if (longer->p[i] != 0) {
            return a->len > b->len ? 1 : -1;
        }
    }
    return 0;
}

void der_set_of_sorted(der_t *d, const der_item_t *items, size_t n, uint8_t tag)
{
    der_item_t s[8];
    if (n > 8) {
        d->err = -1;
        return;
    }
    for (size_t i = 0; i < n; i++) {
        size_t j = i;
        while (j > 0 && item_cmp(&s[j - 1], &items[i]) > 0) {
            s[j] = s[j - 1];
            j--;
        }
        s[j] = items[i];
    }
    size_t mark = der_size(d);
    for (size_t i = n; i > 0; i--) { /* rueckwaerts: groesstes Element zuerst */
        der_raw(d, s[i - 1].p, s[i - 1].len);
    }
    der_wrap(d, mark, tag);
}
