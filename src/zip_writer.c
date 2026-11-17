/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <string.h>
#include "zip_writer.h"
#include "esp_rom_crc.h"
#include "sdkconfig.h"

#define SIG_LOCAL   0x04034b50u
#define SIG_CENTRAL 0x02014b50u
#define SIG_EOCD    0x06054b50u
#define FLAG_UTF8   0x0800u

static void put16(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v & 0xffff); put16(p + 2, v >> 16); }

esp_err_t zip_dos_time(time_t t, uint16_t *dos_time, uint16_t *dos_date)
{
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    int year = tm.tm_year + 1900;
    if (year < 1980 || year > 2107) {
        return ESP_ERR_INVALID_ARG;
    }
    *dos_time = (uint16_t)((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    *dos_date = (uint16_t)(((year - 1980) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
    return ESP_OK;
}

static esp_err_t emit(zip_writer_t *zw, const void *buf, size_t len)
{
    esp_err_t err = zw->write(buf, len, zw->ctx);
    if (err == ESP_OK) {
        zw->offset += (uint32_t)len;
    }
    return err;
}

esp_err_t zip_writer_init(zip_writer_t *zw, asics_write_cb_t write, void *ctx, time_t mtime)
{
    if (!zw || !write) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(zw, 0, sizeof(*zw));
    zw->write = write;
    zw->ctx = ctx;
    return zip_dos_time(mtime, &zw->dos_time, &zw->dos_date);
}

esp_err_t zip_writer_begin_entry(zip_writer_t *zw, const zip_entry_t *e)
{
    if (zw->count >= ZIP_MAX_ENTRIES || e->method != ZIP_METHOD_STORE ||
        e->comp_size != e->uncomp_size || e->name_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    zip_entry_t *z = &zw->entries[zw->count];
    *z = *e;
    z->local_offset = zw->offset;
    uint8_t h[30];
    put32(h + 0, SIG_LOCAL);
    put16(h + 4, 10);          /* version needed: 1.0 (STORE) */
    put16(h + 6, z->flags);
    put16(h + 8, z->method);
    put16(h + 10, zw->dos_time);
    put16(h + 12, zw->dos_date);
    put32(h + 14, z->crc32);
    put32(h + 18, z->comp_size);
    put32(h + 22, z->uncomp_size);
    put16(h + 26, z->name_len);
    put16(h + 28, 0);          /* kein Extra-Feld */
    esp_err_t err = emit(zw, h, sizeof(h));
    if (err == ESP_OK) {
        err = emit(zw, z->name, z->name_len);
    }
    if (err == ESP_OK) {
        zw->count++;
    }
    return err;
}

esp_err_t zip_writer_write_data(zip_writer_t *zw, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t n = len > CONFIG_ASICS_WRITE_CHUNK ? CONFIG_ASICS_WRITE_CHUNK : len;
        esp_err_t err = emit(zw, data, n);
        if (err != ESP_OK) {
            return err;
        }
        data += n;
        len -= n;
    }
    return ESP_OK;
}

esp_err_t zip_writer_add_stored(zip_writer_t *zw, const char *name, const uint8_t *data, size_t len)
{
    if (!name || (!data && len)) {
        return ESP_ERR_INVALID_ARG;
    }
#if SIZE_MAX > 0xFFFFFFFFu
    if (len > 0xFFFFFFFFu) { /* kein ZIP64 */
        return ESP_ERR_INVALID_ARG;
    }
#endif
    size_t nl = strlen(name);
    if (nl == 0 || nl > 0xFFFF) {
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t crc = 0;
    for (size_t off = 0; off < len;) {
        size_t n = len - off > 0x10000 ? 0x10000 : len - off;
        crc = esp_rom_crc32_le(crc, data + off, (uint32_t)n);
        off += n;
    }
    uint16_t flags = 0;
    for (size_t i = 0; i < nl; i++) {
        if ((uint8_t)name[i] >= 0x80) {
            flags |= FLAG_UTF8;
        }
    }
    zip_entry_t e = {
        .name = name, .name_len = (uint16_t)nl, .method = ZIP_METHOD_STORE, .flags = flags,
        .crc32 = crc, .comp_size = (uint32_t)len, .uncomp_size = (uint32_t)len,
    };
    esp_err_t err = zip_writer_begin_entry(zw, &e);
    if (err == ESP_OK) {
        err = zip_writer_write_data(zw, data, len);
    }
    return err;
}

esp_err_t zip_writer_finish(zip_writer_t *zw)
{
    uint32_t cd_start = zw->offset;
    for (size_t i = 0; i < zw->count; i++) {
        const zip_entry_t *z = &zw->entries[i];
        uint8_t h[46];
        put32(h + 0, SIG_CENTRAL);
        put16(h + 4, 20);          /* version made by: MS-DOS, 2.0 */
        put16(h + 6, 10);
        put16(h + 8, z->flags);
        put16(h + 10, z->method);
        put16(h + 12, zw->dos_time);
        put16(h + 14, zw->dos_date);
        put32(h + 16, z->crc32);
        put32(h + 20, z->comp_size);
        put32(h + 24, z->uncomp_size);
        put16(h + 28, z->name_len);
        put16(h + 30, 0);
        put16(h + 32, 0);
        put16(h + 34, 0);
        put16(h + 36, 0);
        put32(h + 38, 0);
        put32(h + 42, z->local_offset);
        esp_err_t err = emit(zw, h, sizeof(h));
        if (err == ESP_OK) {
            err = emit(zw, z->name, z->name_len);
        }
        if (err != ESP_OK) {
            return err;
        }
    }
    uint32_t cd_size = zw->offset - cd_start;
    uint8_t e[22];
    put32(e + 0, SIG_EOCD);
    put16(e + 4, 0);
    put16(e + 6, 0);
    put16(e + 8, (uint16_t)zw->count);
    put16(e + 10, (uint16_t)zw->count);
    put32(e + 12, cd_size);
    put32(e + 16, cd_start);
    put16(e + 20, 0);
    return emit(zw, e, sizeof(e));
}
