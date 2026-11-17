/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/*
 * Minimaler streamender ZIP-Writer (nur STORE, kein ZIP64, kein Data Descriptor).
 *
 * Die Schnittstelle trennt Eintragsbeschreibung (zip_entry_t mit method,
 * Groessen, CRC) vom Datenstrom, damit spaeter Kompression (DEFLATE) ergaenzt
 * werden kann: dann muessten comp_size/crc vorab bzw. ueber einen Data Descriptor
 * bekannt gemacht werden. Aktuell wird ausschliesslich ZIP_METHOD_STORE akzeptiert.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "esp_err.h"
#include "asics_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZIP_METHOD_STORE 0
#define ZIP_MAX_ENTRIES  4

typedef struct {
    const char *name;     /**< muss bis zip_writer_finish() gueltig bleiben */
    uint16_t name_len;
    uint16_t method;      /**< nur ZIP_METHOD_STORE */
    uint16_t flags;
    uint32_t crc32;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint32_t local_offset;
} zip_entry_t;

typedef struct {
    asics_write_cb_t write;
    void *ctx;
    uint32_t offset;       /**< bisher geschriebene Bytes */
    uint16_t dos_time;
    uint16_t dos_date;
    size_t count;
    zip_entry_t entries[ZIP_MAX_ENTRIES];
} zip_writer_t;

/** DOS-Zeit/-Datum aus Unix-Zeit (UTC, 1980..2107). */
esp_err_t zip_dos_time(time_t t, uint16_t *dos_time, uint16_t *dos_date);

esp_err_t zip_writer_init(zip_writer_t *zw, asics_write_cb_t write, void *ctx, time_t mtime);

/** Eintrag beginnen (Local Header schreiben). e->crc32/Groessen muessen vorab bekannt sein. */
esp_err_t zip_writer_begin_entry(zip_writer_t *zw, const zip_entry_t *e);
/** Rohdaten des aktuellen Eintrags (ohne Kopie, in Chunks). */
esp_err_t zip_writer_write_data(zip_writer_t *zw, const uint8_t *data, size_t len);

/** Komfort: STORE-Eintrag (CRC wird berechnet, Daten gestreamt). */
esp_err_t zip_writer_add_stored(zip_writer_t *zw, const char *name, const uint8_t *data, size_t len);

/** Central Directory + End of Central Directory schreiben. */
esp_err_t zip_writer_finish(zip_writer_t *zw);

#ifdef __cplusplus
}
#endif
