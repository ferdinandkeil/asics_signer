/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Minimaler, begrenzungssicherer DER-Leser (nur Definite-Length) fuer die TSA-Antwortpruefung. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} der_rd_t;

/** Naechstes TLV lesen und weiterruecken. val/vlen = Inhalt, tlv/tlen = komplettes Element (optional). */
static inline bool der_rd_next(der_rd_t *r, uint8_t *tag, const uint8_t **val, size_t *vlen,
                               const uint8_t **tlv, size_t *tlen)
{
    const uint8_t *s = r->p;
    if (r->end - s < 2) {
        return false;
    }
    uint8_t t = s[0];
    size_t l = s[1];
    const uint8_t *q = s + 2;
    if ((t & 0x1f) == 0x1f) { /* High-Tag-Number nicht unterstuetzt */
        return false;
    }
    if (l & 0x80) {
        size_t nb = l & 0x7f;
        if (nb == 0 || nb > 3 || (size_t)(r->end - q) < nb) {
            return false;
        }
        l = 0;
        while (nb--) {
            l = (l << 8) | *q++;
        }
    }
    if ((size_t)(r->end - q) < l) {
        return false;
    }
    *tag = t;
    *val = q;
    *vlen = l;
    if (tlv) *tlv = s;
    if (tlen) *tlen = (size_t)(q - s) + l;
    r->p = q + l;
    return true;
}

/** Naechstes Element muss den Tag want haben; liefert Leser ueber dessen Inhalt. */
static inline bool der_rd_enter(der_rd_t *r, uint8_t want, der_rd_t *sub)
{
    uint8_t t;
    const uint8_t *v;
    size_t l;
    if (!der_rd_next(r, &t, &v, &l, NULL, NULL) || t != want) {
        return false;
    }
    sub->p = v;
    sub->end = v + l;
    return true;
}

static inline bool der_rd_done(const der_rd_t *r) { return r->p == r->end; }
/** Tag des naechsten Elements (0, wenn keines). */
static inline uint8_t der_rd_peek(const der_rd_t *r) { return r->p < r->end ? r->p[0] : 0; }
