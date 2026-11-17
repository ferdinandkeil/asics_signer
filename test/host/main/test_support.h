/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
/* Gemeinsame Hilfen der Host-Tests. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "unity.h"
#include "esp_err.h"

#define TEST_TIME ((time_t)1768478400) /* 2026-01-15 12:00:00 UTC */

typedef struct { uint8_t *buf; size_t len; size_t cap; int calls; int fail_at; } sink_t;
esp_err_t sink_write(const void *buf, size_t len, void *ctx);
void sink_free(sink_t *s);

/** Datei aus Verzeichnis ASICS_TEST_PKI lesen (malloc). */
uint8_t *test_read_pki(const char *name, size_t *len);
/** PEM->DER (malloc). */
uint8_t *test_pem_to_der(const char *name, size_t *len);
/** Ausgabedatei in ASICS_TEST_OUT schreiben. */
void test_write_out(const char *name, const void *data, size_t len);
/** Fixture-Schluessel (dev.key) in den RAM-NVS laden (Testhilfe, nicht Teil der API). */
void test_install_device_key(void);
/** Geraetezertifikat + Kette (Dateinamen, Issuing-CA zuerst) importieren; Rueckgabe = Importergebnis. */
esp_err_t test_import_chain(const char *dev, const char *const *chain, size_t n);
void test_load_certs(const char *dev, const char *ca);
