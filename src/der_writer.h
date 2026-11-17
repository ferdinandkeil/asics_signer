/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Duenner Wrapper um mbedtls/asn1write.h. mbedtls schreibt rueckwaerts
 * (vom Pufferende zum Anfang); dieselbe Konvention gilt hier: Elemente
 * werden in umgekehrter Reihenfolge geschrieben, Container danach mit
 * der_wrap() umschlossen. Fehler sind "klebrig" (d->err).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *start; /**< Pufferanfang */
    uint8_t *p;     /**< aktueller Beginn der geschriebenen Daten */
    uint8_t *end;   /**< Pufferende */
    int err;        /**< != 0 nach Ueberlauf/Fehler */
} der_t;

/** Maximale Elementzahl von der_set_of_sorted() (Zertifikate im CMS-Set: Geraet + CAs). */
#define DER_SET_MAX 8

typedef struct {
    const uint8_t *p;
    size_t len;
} der_item_t;

void der_init(der_t *d, uint8_t *buf, size_t size);
static inline size_t der_size(const der_t *d) { return (size_t)(d->end - d->p); }
static inline const uint8_t *der_data(const der_t *d) { return d->p; }
static inline esp_err_t der_status(const der_t *d) { return d->err ? ESP_ERR_NO_MEM : ESP_OK; }

/** Rohbytes voranstellen. */
void der_raw(der_t *d, const uint8_t *data, size_t len);
/** Laenge + Tag um alles seit mark (= der_size zu Beginn) legen. */
void der_wrap(der_t *d, size_t mark, uint8_t tag);
/** OID (nur Inhaltsbytes) als OBJECT IDENTIFIER. */
void der_oid(der_t *d, const uint8_t *oid, size_t len);
void der_int(der_t *d, int v);
/** INTEGER aus bereits kodierten Inhaltsbytes (z. B. Zertifikats-Seriennummer). */
void der_int_raw(der_t *d, const uint8_t *content, size_t len);
void der_octet_string(der_t *d, const uint8_t *data, size_t len);
/** BIT STRING mit 0 unused bits. */
/** BOOLEAN. */
void der_bool(der_t *d, bool v);
/** INTEGER aus vorzeichenlosen Big-Endian-Bytes (fuehrende Nullen entfernt, ggf. 0x00 vorangestellt). */
void der_uint_be(der_t *d, const uint8_t *be, size_t len);
void der_bit_string(der_t *d, const uint8_t *data, size_t len);
void der_string(der_t *d, uint8_t tag, const char *s, size_t len);
/**
 * SET OF aus fertig kodierten Elementen schreiben, DER-sortiert
 * (X.690 11.6: aufsteigend nach Oktettvergleich). n <= DER_SET_MAX.
 */
void der_set_of_sorted(der_t *d, const der_item_t *items, size_t n, uint8_t tag);

#ifdef __cplusplus
}
#endif
