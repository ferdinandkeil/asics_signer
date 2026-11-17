/*
 * SPDX-FileCopyrightText: 2026 Ferdinand Keil
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>
#include "tsa_verify.h"
#include "asics_signer.h"
#include "cert_store.h"
#include "esp_log.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "asn1_oids.h"

static const char *TAG = "asics_tsa";


#define FAIL(msg) do { ESP_LOGE(TAG, "%s", msg); err = ASICS_ERR_TSA_INVALID; goto done; } while (0)
#define OIDEQ(v, vl, o) ((vl) == sizeof(o) && memcmp((v), (o), sizeof(o)) == 0)

/* Hash-Algorithmus aus OID; sha1 nur fuer ESS (allow_sha1) */
static mbedtls_md_type_t md_from_oid(const uint8_t *v, size_t vl, bool allow_sha1)
{
    if (OIDEQ(v, vl, ASN1_OID_SHA256)) return MBEDTLS_MD_SHA256;
    if (OIDEQ(v, vl, ASN1_OID_SHA384)) return MBEDTLS_MD_SHA384;
    if (OIDEQ(v, vl, ASN1_OID_SHA512)) return MBEDTLS_MD_SHA512;
    if (allow_sha1 && OIDEQ(v, vl, ASN1_OID_SHA1)) return MBEDTLS_MD_SHA1;
    return MBEDTLS_MD_NONE;
}

static bool md_hash(mbedtls_md_type_t md, const uint8_t *in, size_t len, uint8_t *out, size_t *olen)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md);
    if (!info) return false;
    *olen = mbedtls_md_get_size(info);
    return mbedtls_md(info, in, len, out) == 0;
}

/* Extensions des TSA-Zertifikats: EKU kritisch und ausschliesslich timeStamping */
static bool eku_ok(const mbedtls_x509_crt *c)
{
    der_rd_t top = {c->v3_ext.p, c->v3_ext.p + c->v3_ext.len}, exts, ext;
    if (c->v3_ext.p == NULL || !der_rd_enter(&top, 0x30, &exts)) {
        return false;
    }
    while (!der_rd_done(&exts)) {
        uint8_t tag;
        const uint8_t *v;
        size_t vl;
        if (!der_rd_enter(&exts, 0x30, &ext) || !der_rd_next(&ext, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {
            return false;
        }
        if (!OIDEQ(v, vl, ASN1_OID_EXT_EKU)) {
            continue;
        }
        bool critical = false;
        if (der_rd_peek(&ext) == 0x01) {
            if (!der_rd_next(&ext, &tag, &v, &vl, NULL, NULL) || vl != 1) return false;
            critical = v[0] != 0;
        }
        der_rd_t oct, seq;
        if (!critical || !der_rd_enter(&ext, 0x04, &oct) || !der_rd_enter(&oct, 0x30, &seq)) {
            return false;
        }
        if (!der_rd_next(&seq, &tag, &v, &vl, NULL, NULL) || tag != 0x06 || !OIDEQ(v, vl, ASN1_OID_KP_TIMESTAMPING)) {
            return false;
        }
        return der_rd_done(&seq); /* nur diese EKU */
    }
    return false;
}

/* Signatur pruefen: signatureAlgorithm muss zum Schluesseltyp und zum digestAlgorithm passen.
 * Unterstuetzt: ecdsa-with-SHA256/384/512; rsaEncryption und sha256/384/512WithRSAEncryption (PKCS#1 v1.5);
 * RSASSA-PSS (Hash/MGF1/Salt-Laenge aus den Parametern). Alles andere -> false. */
static bool verify_signature(mbedtls_pk_context *pk, mbedtls_md_type_t md, const uint8_t *oid, size_t oid_len,
                             der_rd_t *params, const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len)
{
    mbedtls_pk_type_t kt = mbedtls_pk_get_type(pk);
    mbedtls_md_type_t alg_md = MBEDTLS_MD_NONE; /* in der Algorithmus-OID festgelegter Hash (NONE: offen) */
    bool ecdsa = false, rsa_v15 = false;
    if (OIDEQ(oid, oid_len, ASN1_OID_ECDSA_SHA256)) { ecdsa = true; alg_md = MBEDTLS_MD_SHA256; }
    else if (OIDEQ(oid, oid_len, ASN1_OID_ECDSA_SHA384)) { ecdsa = true; alg_md = MBEDTLS_MD_SHA384; }
    else if (OIDEQ(oid, oid_len, ASN1_OID_ECDSA_SHA512)) { ecdsa = true; alg_md = MBEDTLS_MD_SHA512; }
    else if (OIDEQ(oid, oid_len, ASN1_OID_RSA_ENCRYPTION)) { rsa_v15 = true; }
    else if (OIDEQ(oid, oid_len, ASN1_OID_SHA256_RSA)) { rsa_v15 = true; alg_md = MBEDTLS_MD_SHA256; }
    else if (OIDEQ(oid, oid_len, ASN1_OID_SHA384_RSA)) { rsa_v15 = true; alg_md = MBEDTLS_MD_SHA384; }
    else if (OIDEQ(oid, oid_len, ASN1_OID_SHA512_RSA)) { rsa_v15 = true; alg_md = MBEDTLS_MD_SHA512; }

    if (ecdsa || rsa_v15) {
        if ((ecdsa && kt != MBEDTLS_PK_ECKEY) || (rsa_v15 && kt != MBEDTLS_PK_RSA) ||
            (alg_md != MBEDTLS_MD_NONE && alg_md != md)) {
            return false;
        }
        return mbedtls_pk_verify(pk, md, hash, hash_len, sig, sig_len) == 0;
    }
    if (!OIDEQ(oid, oid_len, ASN1_OID_RSASSA_PSS) || kt != MBEDTLS_PK_RSA) {
        return false;
    }
    /* RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm (Default sha1), [1] maskGenAlgorithm (Default mgf1SHA1),
     * [2] saltLength (Default 20), [3] trailerField (Default 1) } - SHA-1 wird nicht akzeptiert */
    der_rd_t p, hrd, mrd, malg, mhash;
    uint8_t tag;
    const uint8_t *v;
    size_t vl;
    if (!der_rd_enter(params, 0x30, &p) || der_rd_peek(&p) != 0xA0 || !der_rd_enter(&p, 0xA0, &hrd) ||
        !der_rd_enter(&hrd, 0x30, &mhash) || !der_rd_next(&mhash, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {
        return false;
    }
    mbedtls_md_type_t hmd = md_from_oid(v, vl, false);
    if (hmd == MBEDTLS_MD_NONE || hmd != md) {
        return false;
    }
    if (der_rd_peek(&p) != 0xA1 || !der_rd_enter(&p, 0xA1, &mrd) || !der_rd_enter(&mrd, 0x30, &malg) ||
        !der_rd_next(&malg, &tag, &v, &vl, NULL, NULL) || tag != 0x06 || !OIDEQ(v, vl, ASN1_OID_MGF1) ||
        !der_rd_enter(&malg, 0x30, &mhash) || !der_rd_next(&mhash, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {
        return false;
    }
    mbedtls_md_type_t mgf = md_from_oid(v, vl, false);
    if (mgf == MBEDTLS_MD_NONE) {
        return false;
    }
    int salt = 20;
    if (der_rd_peek(&p) == 0xA2) {
        der_rd_t srd;
        if (!der_rd_enter(&p, 0xA2, &srd) || !der_rd_next(&srd, &tag, &v, &vl, NULL, NULL) || tag != 0x02 || vl != 1 ||
            (v[0] & 0x80)) {
            return false;
        }
        salt = v[0];
    } /* sonst Default 20 */
    if (der_rd_peek(&p) == 0xA3) {   /* trailerField muss 1 sein */
        der_rd_t trd;
        if (!der_rd_enter(&p, 0xA3, &trd) || !der_rd_next(&trd, &tag, &v, &vl, NULL, NULL) || tag != 0x02 || vl != 1 ||
            v[0] != 1) {
            return false;
        }
    }
    if (!der_rd_done(&p)) {
        return false;
    }
    mbedtls_pk_rsassa_pss_options opt = {.mgf1_hash_id = mgf, .expected_salt_len = salt};
    return mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &opt, pk, md, hash, hash_len, sig, sig_len) == 0;
}

typedef struct {
    time_t gen_time;
    bool ok;
} time_check_t;

/* mbedtls-Verify-Callback: Gueltigkeit jedes Kettenglieds gegen genTime (statt gegen die Systemuhr) */
static int vrfy_time_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    (void)depth;
    time_check_t *tc = ctx;
    *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    if (asics_cert_check_validity_crt(crt, tc->gen_time) != ESP_OK) {
        tc->ok = false;
    }
    return 0;
}

esp_err_t tsa_verify_token(const tsa_token_t *t, const mbedtls_x509_crt *ca, time_t gen_time)
{
    esp_err_t err = ASICS_ERR_TSA_INVALID;
    mbedtls_x509_crt *tsa = calloc(1, sizeof(*tsa));
    uint8_t *attrs_copy = NULL;
    if (!tsa) {
        return ESP_ERR_NO_MEM;
    }
    mbedtls_x509_crt_init(tsa);

    /* --- SignerInfo --- */
    der_rd_t si = t->signer_info, sid_rd, alg, attrs, sigalg;
    uint8_t tag;
    const uint8_t *v, *attrs_tlv, *sid_tlv;
    size_t vl, attrs_tlen, sid_tlen;
    if (!der_rd_next(&si, &tag, &v, &vl, NULL, NULL) || tag != 0x02 || vl != 1 || v[0] != 1) {
        FAIL("SignerInfo: Version != 1");
    }
    if (!der_rd_next(&si, &tag, &v, &vl, &sid_tlv, &sid_tlen) || (tag != 0x30 && tag != 0x80)) {
        FAIL("SignerInfo: sid defekt");
    }
    bool sid_is_issuer_serial = tag == 0x30;
    const uint8_t *sid_val = v;
    size_t sid_vlen = vl;
    (void)sid_rd; (void)sid_tlv; (void)sid_tlen;
    if (!der_rd_enter(&si, 0x30, &alg) || !der_rd_next(&alg, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {
        FAIL("SignerInfo: digestAlgorithm defekt");
    }
    mbedtls_md_type_t md = md_from_oid(v, vl, false);
    if (md == MBEDTLS_MD_NONE) {
        FAIL("SignerInfo: Digest-Algorithmus nicht unterstuetzt");
    }
    if (der_rd_peek(&si) != 0xA0 || !der_rd_next(&si, &tag, &v, &vl, &attrs_tlv, &attrs_tlen)) {
        FAIL("SignerInfo: signedAttrs fehlen");
    }
    attrs.p = v;
    attrs.end = v + vl;
    const uint8_t *sigalg_oid;
    size_t sigalg_oid_len;
    if (!der_rd_enter(&si, 0x30, &sigalg) || !der_rd_next(&sigalg, &tag, &sigalg_oid, &sigalg_oid_len, NULL, NULL) ||
        tag != 0x06) {
        FAIL("SignerInfo: signatureAlgorithm defekt");
    }
    const uint8_t *sig;
    size_t sig_len;
    if (!der_rd_next(&si, &tag, &sig, &sig_len, NULL, NULL) || tag != 0x04) {
        FAIL("SignerInfo: signature defekt");
    }

    /* --- Signed Attributes: content-type, message-digest, ESS --- */
    bool got_ct = false, got_md = false, got_ess = false;
    uint8_t ess_hash[64];
    size_t ess_hash_len = 0;
    mbedtls_md_type_t ess_md = MBEDTLS_MD_SHA256;
    while (!der_rd_done(&attrs)) {
        der_rd_t at, vals;
        if (!der_rd_enter(&attrs, 0x30, &at) || !der_rd_next(&at, &tag, &v, &vl, NULL, NULL) || tag != 0x06) {
            FAIL("signedAttrs defekt");
        }
        const uint8_t *oid = v;
        size_t oid_len = vl;
        if (!der_rd_enter(&at, 0x31, &vals)) {
            FAIL("signedAttrs: Attributwert defekt");
        }
        if (OIDEQ(oid, oid_len, ASN1_OID_CONTENT_TYPE)) {
            if (!der_rd_next(&vals, &tag, &v, &vl, NULL, NULL) || tag != 0x06 || !OIDEQ(v, vl, ASN1_OID_CT_TSTINFO)) {
                FAIL("signedAttrs: content-type != id-ct-TSTInfo");
            }
            got_ct = true;
        } else if (OIDEQ(oid, oid_len, ASN1_OID_MSG_DIGEST)) {
            uint8_t h[64];
            size_t hl;
            if (!der_rd_next(&vals, &tag, &v, &vl, NULL, NULL) || tag != 0x04 ||
                !md_hash(md, t->tstinfo, t->tstinfo_len, h, &hl) || vl != hl || memcmp(h, v, hl) != 0) {
                FAIL("signedAttrs: message-digest stimmt nicht mit dem TSTInfo ueberein");
            }
            got_md = true;
        } else if (OIDEQ(oid, oid_len, ASN1_OID_SIGNING_CERT) || OIDEQ(oid, oid_len, ASN1_OID_SIGNING_CERT_V2)) {
            bool v2 = OIDEQ(oid, oid_len, ASN1_OID_SIGNING_CERT_V2);
            der_rd_t sc, certs, id;
            if (!der_rd_enter(&vals, 0x30, &sc) || !der_rd_enter(&sc, 0x30, &certs) || !der_rd_enter(&certs, 0x30, &id)) {
                FAIL("ESS signing-certificate defekt");
            }
            ess_md = v2 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA1;
            if (der_rd_peek(&id) == 0x30) { /* hashAlgorithm (nur v2; Default SHA-256) */
                der_rd_t a;
                if (!v2 || !der_rd_enter(&id, 0x30, &a) || !der_rd_next(&a, &tag, &v, &vl, NULL, NULL) || tag != 0x06 ||
                    (ess_md = md_from_oid(v, vl, false)) == MBEDTLS_MD_NONE) {
                    FAIL("ESS: hashAlgorithm nicht unterstuetzt");
                }
            }
            if (!der_rd_next(&id, &tag, &v, &vl, NULL, NULL) || tag != 0x04 || vl > sizeof(ess_hash)) {
                FAIL("ESS: certHash defekt");
            }
            memcpy(ess_hash, v, vl);
            ess_hash_len = vl;
            got_ess = true;
        }
    }
    if (!got_ct || !got_md || !got_ess) {
        FAIL("signedAttrs unvollstaendig (content-type, message-digest, ESS erforderlich)");
    }

    /* --- TSA-Zertifikat im Token suchen: ESS-Hash und sid muessen passen --- */
    der_rd_t certs = t->certs;
    bool found = false;
    while (!der_rd_done(&certs)) {
        const uint8_t *ctlv;
        size_t ctlen;
        if (!der_rd_next(&certs, &tag, &v, &vl, &ctlv, &ctlen) || tag != 0x30) {
            FAIL("certificates defekt");
        }
        uint8_t h[64];
        size_t hl;
        if (!md_hash(ess_md, ctlv, ctlen, h, &hl) || hl != ess_hash_len || memcmp(h, ess_hash, hl) != 0) {
            continue;
        }
        if (mbedtls_x509_crt_parse_der(tsa, ctlv, ctlen) != 0) {
            FAIL("TSA-Zertifikat nicht parsebar");
        }
        found = true;
        break;
    }
    if (!found) {
        FAIL("TSA-Zertifikat (ESS-Referenz) nicht im Token enthalten");
    }
    if (sid_is_issuer_serial) { /* sid = IssuerAndSerialNumber { issuer Name, serial INTEGER } */
        der_rd_t isr = {sid_val, sid_val + sid_vlen};
        const uint8_t *itlv, *sv;
        size_t itlen, svl;
        if (!der_rd_next(&isr, &tag, &v, &vl, &itlv, &itlen) || tag != 0x30 ||
            !der_rd_next(&isr, &tag, &sv, &svl, NULL, NULL) || tag != 0x02 ||
            itlen != tsa->issuer_raw.len || memcmp(itlv, tsa->issuer_raw.p, itlen) != 0 ||
            svl != tsa->serial.len || memcmp(sv, tsa->serial.p, svl) != 0) {
            FAIL("SignerInfo.sid passt nicht zum TSA-Zertifikat");
        }
    }

    /* --- Weitere Zertifikate des Tokens als untrusted Zwischenzertifikate an die Kette haengen --- */
    {
        const uint8_t *leaf_der = tsa->raw.p;
        der_rd_t again = t->certs;
        while (!der_rd_done(&again)) {
            const uint8_t *ctlv;
            size_t ctlen;
            if (!der_rd_next(&again, &tag, &v, &vl, &ctlv, &ctlen) || tag != 0x30) {
                FAIL("certificates defekt");
            }
            if (ctlen == tsa->raw.len && memcmp(ctlv, leaf_der, ctlen) == 0) {
                continue; /* das TSA-Zertifikat selbst */
            }
            if (mbedtls_x509_crt_parse_der(tsa, ctlv, ctlen) != 0) {
                FAIL("Zertifikat im Token nicht parsebar");
            }
        }
    }

    /* --- Signatur ueber die DER-Signed-Attributes (Tag 0x31 statt 0xA0) --- */
    attrs_copy = malloc(attrs_tlen);
    if (!attrs_copy) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    memcpy(attrs_copy, attrs_tlv, attrs_tlen);
    attrs_copy[0] = 0x31;
    uint8_t dg[64];
    size_t dgl;
    if (!md_hash(md, attrs_copy, attrs_tlen, dg, &dgl)) {
        FAIL("TSA-Signatur: Hash nicht berechenbar");
    }
    if (!verify_signature(&tsa->pk, md, sigalg_oid, sigalg_oid_len, &sigalg, dg, dgl, sig, sig_len)) {
        FAIL("TSA-Signatur ungueltig oder Signaturalgorithmus nicht unterstuetzt");
    }

    /* --- Zertifikatspruefung --- */
    if (!eku_ok(tsa)) {
        FAIL("TSA-Zertifikat: kritische EKU timeStamping (ausschliesslich) fehlt");
    }
    /* Kette: TSA-Zertifikat (Blatt) + untrusted Zwischenzertifikate aus dem Token -> eingebettete TSA-CA (Anker).
     * Die Zeitpruefung erfolgt im Callback fuer jedes tatsaechlich verwendete Kettenglied gegen genTime. */
    time_check_t tc = {.gen_time = gen_time, .ok = true};
    uint32_t flags = 0;
    int rc = mbedtls_x509_crt_verify(tsa, (mbedtls_x509_crt *)ca /* mbedtls aendert den Anker nicht */, NULL, NULL, &flags,
                                    vrfy_time_cb, &tc);
    if ((rc != 0 && rc != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) || flags != 0) {
        FAIL("TSA-Zertifikat nicht ueber die eingebettete TSA-CA verifizierbar");
    }
    if (!tc.ok || asics_cert_check_validity_crt(ca, gen_time) != ESP_OK) {
        FAIL("Zertifikat der TSA-Kette zur genTime nicht gueltig");
    }
    err = ESP_OK;
done:
    free(attrs_copy);
    mbedtls_x509_crt_free(tsa);
    free(tsa);
    return err;
}
