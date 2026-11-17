/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <string.h>
#include "tsa_resp.h"
#include "asics_signer.h"
#include "esp_log.h"
#include "asn1_oids.h"

static const char *TAG = "asics_tsa";


#define INVALID(msg) do { ESP_LOGE(TAG, "%s", msg); return ASICS_ERR_TSA_INVALID; } while (0)

esp_err_t tsa_parse_response(const uint8_t *resp, size_t len, tsa_resp_t *out)
{
    der_rd_t top = {resp, resp + len}, r, st;
    if (!resp || !der_rd_enter(&top, 0x30, &r) || !der_rd_done(&top)) {
        INVALID("TimeStampResp: Struktur defekt");
    }
    if (!der_rd_enter(&r, 0x30, &st)) {
        INVALID("PKIStatusInfo fehlt");
    }
    uint8_t t;
    const uint8_t *v;
    size_t vl;
    if (!der_rd_next(&st, &t, &v, &vl, NULL, NULL) || t != 0x02 || vl != 1) {
        INVALID("PKIStatus defekt");
    }
    if (v[0] != 0 && v[0] != 1) { /* granted, grantedWithMods */
        ESP_LOGW(TAG, "TSA lehnt ab: PKIStatus %d", v[0]);
        return ASICS_ERR_TSA_REJECTED;
    }
    const uint8_t *tlv;
    size_t tlen;
    if (!der_rd_next(&r, &t, &v, &vl, &tlv, &tlen) || t != 0x30 || !der_rd_done(&r)) {
        INVALID("TimeStampToken fehlt oder Antwort hat Reste");
    }
    out->token = tlv;
    out->token_len = tlen;
    return ESP_OK;
}

esp_err_t tsa_parse_token(const uint8_t *token, size_t len, tsa_token_t *t)
{
    der_rd_t top = {token, token + len}, ci, ex, sd, eci, ec, si_set;
    uint8_t tag;
    const uint8_t *v;
    size_t vl;
    memset(t, 0, sizeof(*t));
    if (!der_rd_enter(&top, 0x30, &ci) || !der_rd_done(&top) ||
        !der_rd_next(&ci, &tag, &v, &vl, NULL, NULL) || tag != 0x06 || vl != sizeof(ASN1_OID_SIGNED_DATA) ||
        memcmp(v, ASN1_OID_SIGNED_DATA, vl) != 0 || !der_rd_enter(&ci, 0xA0, &ex) || !der_rd_enter(&ex, 0x30, &sd)) {
        INVALID("Token ist kein SignedData");
    }
    if (!der_rd_next(&sd, &tag, &v, &vl, NULL, NULL) || tag != 0x02 /* version */ ||
        !der_rd_next(&sd, &tag, &v, &vl, NULL, NULL) || tag != 0x31 /* digestAlgorithms */ ||
        !der_rd_enter(&sd, 0x30, &eci) ||
        !der_rd_next(&eci, &tag, &v, &vl, NULL, NULL) || tag != 0x06 || vl != sizeof(ASN1_OID_CT_TSTINFO) ||
        memcmp(v, ASN1_OID_CT_TSTINFO, vl) != 0 || !der_rd_enter(&eci, 0xA0, &ec) ||
        !der_rd_next(&ec, &tag, &v, &vl, NULL, NULL) || tag != 0x04) {
        INVALID("eContentType ist nicht id-ct-TSTInfo");
    }
    t->tstinfo = v;
    t->tstinfo_len = vl;
    if (der_rd_peek(&sd) == 0xA0) { /* certificates [0] */
        if (!der_rd_enter(&sd, 0xA0, &t->certs)) {
            INVALID("certificates defekt");
        }
    }
    if (der_rd_peek(&sd) == 0xA1 && !der_rd_next(&sd, &tag, &v, &vl, NULL, NULL)) { /* crls ignorieren */
        INVALID("crls defekt");
    }
    if (!der_rd_enter(&sd, 0x31, &si_set) || !der_rd_enter(&si_set, 0x30, &t->signer_info) ||
        !der_rd_done(&si_set) || !der_rd_done(&sd)) {
        INVALID("genau ein SignerInfo erforderlich");
    }
    return ESP_OK;
}

static int days_from_civil(int y, unsigned m, unsigned d)
{
    y -= m <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int)doe - 719468;
}

bool tsa_parse_generalized_time(const uint8_t *s, size_t len, time_t *out)
{
    if (len < 15 || s[len - 1] != 'Z') {
        return false;
    }
    int f[7] = {4, 2, 2, 2, 2, 2};
    int vals[6], pos = 0;
    for (int i = 0; i < 6; i++) {
        int v = 0;
        for (int k = 0; k < f[i]; k++, pos++) {
            if (s[pos] < '0' || s[pos] > '9') {
                return false;
            }
            v = v * 10 + (s[pos] - '0');
        }
        vals[i] = v;
    }
    if (pos != 14) {
        return false;
    }
    if (len > 15) { /* Sekundenbruchteil ".f+" */
        if (s[14] != '.' || len < 17) {
            return false;
        }
        for (size_t i = 15; i < len - 1; i++) {
            if (s[i] < '0' || s[i] > '9') {
                return false;
            }
        }
        if (s[len - 2] == '0') { /* DER: keine abschliessenden Nullen im Bruchteil */
            return false;
        }
    }
    if (vals[1] < 1 || vals[1] > 12 || vals[3] > 23 || vals[4] > 59 || vals[5] > 59) {
        return false;
    }
    static const int mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int y = vals[0];
    bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    int dim = mdays[vals[1] - 1] + (vals[1] == 2 && leap ? 1 : 0);
    if (vals[2] < 1 || vals[2] > dim) { /* Tag gegen Monat (inkl. Schaltjahre) */
        return false;
    }
    int64_t days = days_from_civil(vals[0], (unsigned)vals[1], (unsigned)vals[2]);
    *out = (time_t)(days * 86400 + vals[3] * 3600 + vals[4] * 60 + vals[5]);
    return true;
}

/* INTEGER-Inhalte als vorzeichenlose Zahl vergleichen (fuehrende Nullen ignorieren) */
static bool uint_equal(const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    while (al > 0 && a[0] == 0) { a++; al--; }
    while (bl > 0 && b[0] == 0) { b++; bl--; }
    return al == bl && memcmp(a, b, al) == 0;
}

esp_err_t tsa_check_tstinfo(const uint8_t *tstinfo, size_t len, const tsa_expect_t *e, time_t *gen_time)
{
    der_rd_t top = {tstinfo, tstinfo + len}, r, mi, alg;
    uint8_t tag;
    const uint8_t *v;
    size_t vl;
    if (!der_rd_enter(&top, 0x30, &r) || !der_rd_done(&top)) {
        INVALID("TSTInfo defekt");
    }
    if (!der_rd_next(&r, &tag, &v, &vl, NULL, NULL) || tag != 0x02 || vl != 1 || v[0] != 1) {
        INVALID("TSTInfo: Version != 1");
    }
    if (!der_rd_next(&r, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {           /* policy */
        INVALID("TSTInfo: policy fehlt");
    }
    if (!der_rd_enter(&r, 0x30, &mi) || !der_rd_enter(&mi, 0x30, &alg) ||
        !der_rd_next(&alg, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {
        INVALID("TSTInfo: messageImprint defekt");
    }
    if (vl != sizeof(ASN1_OID_SHA256) || memcmp(v, ASN1_OID_SHA256, vl) != 0) {
        INVALID("TSTInfo: messageImprint nicht SHA-256");
    }
    if (!der_rd_next(&mi, &tag, &v, &vl, NULL, NULL) || tag != 0x04 || vl != 32 || memcmp(v, e->digest, 32) != 0) {
        INVALID("TSTInfo: messageImprint stimmt nicht mit der Anfrage ueberein");
    }
    if (!der_rd_next(&r, &tag, &v, &vl, NULL, NULL) || tag != 0x02) {           /* serialNumber */
        INVALID("TSTInfo: serialNumber fehlt");
    }
    time_t gt;
    if (!der_rd_next(&r, &tag, &v, &vl, NULL, NULL) || tag != 0x18 || !tsa_parse_generalized_time(v, vl, &gt)) {
        INVALID("TSTInfo: genTime defekt");
    }
    if (der_rd_peek(&r) == 0x30 && !der_rd_next(&r, &tag, &v, &vl, NULL, NULL)) { /* accuracy */
        INVALID("TSTInfo: accuracy defekt");
    }
    if (der_rd_peek(&r) == 0x01 && !der_rd_next(&r, &tag, &v, &vl, NULL, NULL)) { /* ordering */
        INVALID("TSTInfo: ordering defekt");
    }
    if (!der_rd_next(&r, &tag, &v, &vl, NULL, NULL) || tag != 0x02) {           /* nonce */
        INVALID("TSTInfo: Nonce fehlt");
    }
    if (!uint_equal(v, vl, e->nonce, e->nonce_len)) {
        INVALID("TSTInfo: Nonce stimmt nicht");
    }
    int64_t diff = (int64_t)gt - (int64_t)e->now;
    if (diff < 0) diff = -diff;
    if (diff > (int64_t)e->tolerance_s) {
        ESP_LOGE(TAG, "genTime weicht %lld s von der Geraeteuhr ab (Toleranz %u s)", (long long)diff, e->tolerance_s);
        return ASICS_ERR_TSA_INVALID;
    }
    *gen_time = gt;
    return ESP_OK;
}
