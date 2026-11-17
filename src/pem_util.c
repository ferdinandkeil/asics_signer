/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pem_util.h"
#include "mbedtls/base64.h"

size_t asics_pem_encoded_min_size(const char *label, size_t len)
{
    size_t b64max = ((len + 2) / 3) * 4 + 1;
    return 2 * (strlen(label) + 16) + b64max + b64max / 64 + 8;
}

esp_err_t asics_pem_encode(const char *label, const uint8_t *der, size_t len,
                           char *out, size_t out_size, size_t *out_len)
{
    size_t b64max = ((len + 2) / 3) * 4 + 1;
    if (out_size < asics_pem_encoded_min_size(label, len)) {
        return ESP_ERR_NO_MEM;
    }
    char *b64 = out + out_size - b64max; /* Base64 am Pufferende, PEM wird vorne aufgebaut */
    size_t blen = 0;
    if (mbedtls_base64_encode((unsigned char *)b64, b64max, &blen, der, len) != 0) {
        return ESP_ERR_NO_MEM;
    }
    size_t n = (size_t)snprintf(out, out_size, "-----BEGIN %s-----\n", label);
    for (size_t i = 0; i < blen; i += 64) {
        size_t c = blen - i > 64 ? 64 : blen - i;
        /* Ueberlappungsschutz: Der Schreibzeiger (inkl. '\n' nach dieser Zeile, also bis out + n + c)
         * darf den noch ungelesenen Rest (ab b64 + i + c) nicht erreichen. Nach der letzten Zeile gibt
         * es keinen ungelesenen Rest mehr. */
        if (i + c < blen && out + n + c + 1 > b64 + i + c) {
            return ESP_ERR_NO_MEM;
        }
        memmove(out + n, b64 + i, c);
        n += c;
        out[n++] = '\n';
    }
    n += (size_t)snprintf(out + n, out_size - n, "-----END %s-----\n", label);
    if (n >= out_size) {
        return ESP_ERR_NO_MEM;
    }
    *out_len = n;
    return ESP_OK;
}

esp_err_t asics_pem_decode(const char *label, const char *pem, size_t pem_len,
                           uint8_t *der, size_t der_size, size_t *der_len)
{
    const char *pos = pem;
    return asics_pem_decode_next(label, &pos, pem + pem_len, der, der_size, der_len);
}

esp_err_t asics_pem_decode_next(const char *label, const char **ppos, const char *pem_end,
                                uint8_t *der, size_t der_size, size_t *der_len)
{
    const char *pem = *ppos;
    size_t pem_len = (size_t)(pem_end - pem);
    char begin[64], end[64];
    snprintf(begin, sizeof(begin), "-----BEGIN %s-----", label);
    snprintf(end, sizeof(end), "-----END %s-----", label);
    /* pem ist nicht notwendig nullterminiert: Kopie-frei ueber memmem-artige Suche */
    const char *b = NULL, *e = NULL;
    size_t bl = strlen(begin), el = strlen(end);
    for (size_t i = 0; i + bl <= pem_len; i++) {
        if (memcmp(pem + i, begin, bl) == 0) { b = pem + i + bl; break; }
    }
    if (!b) {
        return ESP_ERR_NOT_FOUND;
    }
    for (const char *q = b; q + el <= pem + pem_len; q++) {
        if (memcmp(q, end, el) == 0) { e = q; break; }
    }
    if (!e) {
        return ESP_ERR_INVALID_ARG;
    }
    /* Whitespace entfernen (Zwischenpuffer, da Eingabe const) */
    size_t cap = (size_t)(e - b);
    char *clean = malloc(cap + 1);
    if (!clean) {
        return ESP_ERR_NO_MEM;
    }
    size_t cl = 0;
    for (const char *q = b; q < e; q++) {
        if (*q != '\n' && *q != '\r' && *q != ' ' && *q != '\t') {
            clean[cl++] = *q;
        }
    }
    size_t olen = 0;
    int rc = mbedtls_base64_decode(der, der_size, &olen, (const unsigned char *)clean, cl);
    free(clean);
    *ppos = e + el;
    if (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return ESP_ERR_NO_MEM;
    }
    if (rc != 0 || olen == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    *der_len = olen;
    return ESP_OK;
}

void asics_pem_reader_init(asics_pem_reader_t *r, char *buf, size_t cap, const char *label)
{
    r->buf = buf; r->cap = cap; r->len = 0; r->label = label; r->in_block = false;
    if (cap) buf[0] = 0;
}

asics_pem_state_t asics_pem_reader_feed(asics_pem_reader_t *r, const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
    if (n == 0) {
        return ASICS_PEM_NEED_MORE;
    }
    char marker[64];
    if (!r->in_block) {
        snprintf(marker, sizeof(marker), "-----BEGIN %s-----", r->label);
        if (n != strlen(marker) || strncmp(line, marker, n) != 0) {
            return ASICS_PEM_NEED_MORE;
        }
        r->in_block = true;
    }
    if (r->len + n + 2 > r->cap) {
        return ASICS_PEM_ERROR;
    }
    memcpy(r->buf + r->len, line, n);
    r->len += n;
    r->buf[r->len++] = '\n';
    r->buf[r->len] = 0;
    snprintf(marker, sizeof(marker), "-----END %s-----", r->label);
    if (n == strlen(marker) && strncmp(line, marker, n) == 0) {
        return ASICS_PEM_DONE;
    }
    return ASICS_PEM_NEED_MORE;
}
