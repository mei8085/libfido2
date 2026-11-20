/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Re-signing fuzz harness for libfido2's assertion and self-attestation
 * verification paths.
 *
 * Instead of relying on static, pre-signed wire data, this harness signs
 * freshly constructed assertion/attestation material with embedded,
 * test-only keys (see resign_vectors.h), and then checks the following
 * security invariants on fido_assert_verify() and fido_cred_verify_self():
 *
 * - re-encoding the same signature material (DER round-trip, non-minimal
 *   DER, CBOR re-serialisation of the authdata container) must not change
 *   the verification verdict;
 * - substituting the public key (including algorithm confusion with
 *   ES384/RS256 keys) must never yield FIDO_OK;
 * - substituting the signature, the client data hash, or the credential
 *   ID must never yield FIDO_OK;
 * - requiring UP/UV flags or extensions that the authenticator data does
 *   not attest must never yield FIDO_OK;
 * - self-attestation must not carry an x5c certificate chain.
 *
 * All randomness consumed by the harness is derived from the seed field
 * of the unpacked corpus element (see prng_init()), making every run
 * deterministic for a given input.
 */

#undef NDEBUG

#define _FIDO_INTERNAL

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include "mutator_aux.h"
#include "wiredata_fido2.h"
#include "dummy.h"
#include "resign_vectors.h"

#include "../openbsd-compat/openbsd-compat.h"

enum {
	OPT_NFC = 1,	/* use the NFC transport for the device round-trip */
	OPT_DEVICE = 2,	/* exercise the custom-I/O device round-trip */
	OPT_SELF = 4,	/* exercise the self-attestation path */
	OPT_U2F_FMT = 8,/* self-attestation with fmt "fido-u2f" */

	OPT_EDGE,
	OPT_MASK = (((OPT_EDGE - 1) << 1) - 1),
};

#define MAXCDH	512	/* bounded client data hash used for signing */
#define MAXCRED	256	/* bounded credential id used for signing */
#define MAXSIG	80	/* max DER ECDSA sig (72) or raw EdDSA sig (64) */

/* abort()ing on a violated invariant surfaces the input as a crash */
#define INVARIANT(cond) \
	do { \
		if (!(cond)) \
			abort(); \
	} while (0)

/* Parameter set defining a re-signing verification run. */
struct param {
	char rp_id[MAXSTR];
	int seed;
	int ext;
	struct blob cdh;	/* client data hash */
	struct blob cred;	/* credential ID */
	struct blob sig;	/* attacker-supplied signature */
	struct blob pk;		/* attacker-supplied public key */
	struct blob wire_data;	/* authenticator replies (custom I/O) */
	uint8_t opt;
	uint8_t type;		/* cose algorithm selector */
	uint8_t up;
	uint8_t uv;
};

/* Re-signing key context derived from the embedded test-only vectors. */
struct keyctx {
	int alg;		/* COSE_ES256 or COSE_EDDSA */
	EC_KEY *ec;		/* ES256 signing key */
	EVP_PKEY *ed;		/* Ed25519 signing key */
	es256_pk_t es256_pk;	/* own public keys */
	eddsa_pk_t eddsa_pk;
	es256_pk_t es256_alt;	/* substitute public keys */
	eddsa_pk_t eddsa_alt;
};

/*
 * Collection of HID reports from an authenticator issued with a FIDO2
 * get assertion using the example parameters above.
 */
static const uint8_t dummy_wire_data[] = {
	WIREDATA_CTAP_INIT,
	WIREDATA_CTAP_CBOR_INFO,
	WIREDATA_CTAP_CBOR_ASSERT,
};

struct param *
unpack(const uint8_t *ptr, size_t len)
{
	cbor_item_t *item = NULL, **v;
	struct cbor_load_result cbor;
	struct param *p;
	int ok = -1;

	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (item = cbor_load(ptr, len, &cbor)) == NULL ||
	    cbor.read != len ||
	    cbor_isa_array(item) == false ||
	    cbor_array_is_definite(item) == false ||
	    cbor_array_size(item) != 12 ||
	    (v = cbor_array_handle(item)) == NULL)
		goto fail;

	if (unpack_byte(v[0], &p->uv) < 0 ||
	    unpack_byte(v[1], &p->up) < 0 ||
	    unpack_byte(v[2], &p->opt) < 0 ||
	    unpack_byte(v[3], &p->type) < 0 ||
	    unpack_int(v[4], &p->seed) < 0 ||
	    unpack_int(v[5], &p->ext) < 0 ||
	    unpack_string(v[6], p->rp_id) < 0 ||
	    unpack_blob(v[7], &p->cdh) < 0 ||
	    unpack_blob(v[8], &p->cred) < 0 ||
	    unpack_blob(v[9], &p->sig) < 0 ||
	    unpack_blob(v[10], &p->pk) < 0 ||
	    unpack_blob(v[11], &p->wire_data) < 0)
		goto fail;

	ok = 0;
fail:
	if (ok < 0) {
		free(p);
		p = NULL;
	}

	if (item)
		cbor_decref(&item);

	return p;
}

size_t
pack(uint8_t *ptr, size_t len, const struct param *p)
{
	cbor_item_t *argv[12], *array = NULL;
	size_t cbor_alloc_len, cbor_len = 0;
	unsigned char *cbor = NULL;

	memset(argv, 0, sizeof(argv));

	if ((array = cbor_new_definite_array(12)) == NULL ||
	    (argv[0] = pack_byte(p->uv)) == NULL ||
	    (argv[1] = pack_byte(p->up)) == NULL ||
	    (argv[2] = pack_byte(p->opt)) == NULL ||
	    (argv[3] = pack_byte(p->type)) == NULL ||
	    (argv[4] = pack_int(p->seed)) == NULL ||
	    (argv[5] = pack_int(p->ext)) == NULL ||
	    (argv[6] = pack_string(p->rp_id)) == NULL ||
	    (argv[7] = pack_blob(&p->cdh)) == NULL ||
	    (argv[8] = pack_blob(&p->cred)) == NULL ||
	    (argv[9] = pack_blob(&p->sig)) == NULL ||
	    (argv[10] = pack_blob(&p->pk)) == NULL ||
	    (argv[11] = pack_blob(&p->wire_data)) == NULL)
		goto fail;

	for (size_t i = 0; i < 12; i++)
		if (cbor_array_push(array, argv[i]) == false)
			goto fail;

	if ((cbor_len = cbor_serialize_alloc(array, &cbor,
	    &cbor_alloc_len)) == 0 || cbor_len > len) {
		cbor_len = 0;
		goto fail;
	}

	memcpy(ptr, cbor, cbor_len);
fail:
	for (size_t i = 0; i < 12; i++)
		if (argv[i])
			cbor_decref(&argv[i]);

	if (array)
		cbor_decref(&array);

	free(cbor);

	return cbor_len;
}

size_t
pack_dummy(uint8_t *ptr, size_t len)
{
	struct param dummy;
	uint8_t blob[MAXCORPUS];
	size_t blob_len;

	memset(&dummy, 0, sizeof(dummy));

	dummy.opt = OPT_DEVICE | OPT_SELF;
	dummy.up = 1;
	dummy.ext = FIDO_EXT_HMAC_SECRET;

	strlcpy(dummy.rp_id, resign_rp_id, sizeof(dummy.rp_id));

	dummy.cdh.len = sizeof(resign_cdh);
	dummy.cred.len = sizeof(resign_cred_id);
	dummy.pk.len = sizeof(dummy_es256);
	dummy.sig.len = sizeof(dummy_cdh);

	memcpy(&dummy.cdh.body, &resign_cdh, dummy.cdh.len);
	memcpy(&dummy.cred.body, &resign_cred_id, dummy.cred.len);
	memcpy(&dummy.pk.body, &dummy_es256, dummy.pk.len);
	memcpy(&dummy.sig.body, &dummy_cdh, dummy.sig.len);

	dummy.wire_data.len = sizeof(dummy_wire_data);
	memcpy(&dummy.wire_data.body, &dummy_wire_data, dummy.wire_data.len);

	assert((blob_len = pack(blob, sizeof(blob), &dummy)) != 0);

	if (blob_len > len) {
		memcpy(ptr, blob, len);
		return len;
	}

	memcpy(ptr, blob, blob_len);

	return blob_len;
}

static void
prng_bytes(uint8_t *out, size_t len)
{
	unsigned long v = 0;

	for (size_t i = 0; i < len; i++) {
		if ((i & 3) == 0)
			v = prng_uint32();
		out[i] = (uint8_t)(v & 0xff);
		v >>= 8;
	}
}

static EC_KEY *
es256_key_new(const uint8_t *sk)
{
	const EC_GROUP *g;
	EC_KEY *ec = NULL;
	EC_POINT *q = NULL;
	BIGNUM *d = NULL;
	int ok = -1;

	if ((ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (d = BN_bin2bn(sk, 32, NULL)) == NULL ||
	    (g = EC_KEY_get0_group(ec)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL)
		goto out;

	if (EC_POINT_mul(g, q, d, NULL, NULL, NULL) != 1 ||
	    EC_KEY_set_private_key(ec, d) != 1 ||
	    EC_KEY_set_public_key(ec, q) != 1)
		goto out;

	ok = 0;
out:
	if (ok < 0) {
		EC_KEY_free(ec);
		ec = NULL;
	}

	BN_free(d);
	EC_POINT_free(q);

	return ec;
}

static int
es256_pubkey(const EC_KEY *ec, es256_pk_t *pk)
{
	const EC_GROUP *g;
	const EC_POINT *q;
	BIGNUM *x = NULL, *y = NULL;
	uint8_t xy[64];
	int ok = -1;

	if ((g = EC_KEY_get0_group(ec)) == NULL ||
	    (q = EC_KEY_get0_public_key(ec)) == NULL ||
	    (x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL)
		goto out;

	if (EC_POINT_get_affine_coordinates_GFp(g, q, x, y, NULL) != 1 ||
	    BN_bn2binpad(x, xy, 32) != 32 ||
	    BN_bn2binpad(y, xy + 32, 32) != 32)
		goto out;

	if (es256_pk_from_ptr(pk, xy, sizeof(xy)) != FIDO_OK)
		goto out;

	ok = 0;
out:
	BN_free(x);
	BN_free(y);

	return ok;
}

/*
 * Deterministic ECDSA: derive r and k^-1 from a caller-supplied nonce
 * instead of consuming OpenSSL randomness, so that a given seed always
 * produces the same signature.
 */
static int
es256_sign(EC_KEY *ec, const uint8_t *nonce, const uint8_t *dgst,
    uint8_t *out, size_t *out_len)
{
	const EC_GROUP *g;
	EC_POINT *pt = NULL;
	BN_CTX *bnctx = NULL;
	BIGNUM *k = NULL, *kinv = NULL, *r = NULL, *order = NULL, *x = NULL;
	unsigned int len = 0;
	int ok = -1;

	if ((g = EC_KEY_get0_group(ec)) == NULL ||
	    (bnctx = BN_CTX_new()) == NULL ||
	    (order = BN_new()) == NULL ||
	    (k = BN_bin2bn(nonce, 32, NULL)) == NULL ||
	    (kinv = BN_new()) == NULL ||
	    (r = BN_new()) == NULL ||
	    (x = BN_new()) == NULL ||
	    (pt = EC_POINT_new(g)) == NULL)
		goto out;

	if (EC_GROUP_get_order(g, order, bnctx) != 1 ||
	    BN_nnmod(k, k, order, bnctx) != 1)
		goto out;
	if (BN_is_zero(k))
		goto out;
	if (EC_POINT_mul(g, pt, k, NULL, NULL, bnctx) != 1 ||
	    EC_POINT_get_affine_coordinates_GFp(g, pt, x, NULL,
		bnctx) != 1 ||
	    BN_nnmod(r, x, order, bnctx) != 1)
		goto out;
	if (BN_is_zero(r))
		goto out;
	if (BN_mod_inverse(kinv, k, order, bnctx) == NULL)
		goto out;
	if (ECDSA_sign_ex(0, dgst, SHA256_DIGEST_LENGTH, out, &len, kinv,
	    r, ec) != 1)
		goto out;

	*out_len = len;
	ok = 0;
out:
	BN_free(k);
	BN_free(kinv);
	BN_free(r);
	BN_free(order);
	BN_free(x);
	BN_CTX_free(bnctx);
	EC_POINT_free(pt);

	return ok;
}

static EVP_PKEY *
eddsa_key_new(const uint8_t *sk)
{
	return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
}

static int
eddsa_pubkey(const EVP_PKEY *sk, eddsa_pk_t *pk)
{
	uint8_t x[32];
	size_t len = sizeof(x);

	if (EVP_PKEY_get_raw_public_key(sk, x, &len) != 1 ||
	    len != sizeof(x))
		return -1;
	if (eddsa_pk_from_ptr(pk, x, sizeof(x)) != FIDO_OK)
		return -1;

	return 0;
}

static int
eddsa_sign(EVP_PKEY *sk, const uint8_t *msg, size_t msg_len,
    uint8_t *out, size_t *out_len)
{
	EVP_MD_CTX *ctx = NULL;
	size_t len = 64;
	int ok = -1;

	if ((ctx = EVP_MD_CTX_new()) == NULL)
		goto out;
	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, sk) != 1 ||
	    EVP_DigestSign(ctx, out, &len, msg, msg_len) != 1)
		goto out;

	*out_len = len;
	ok = 0;
out:
	EVP_MD_CTX_free(ctx);

	return ok;
}

static int
keyctx_init(struct keyctx *kc, int alg)
{
	memset(kc, 0, sizeof(*kc));
	kc->alg = alg;

	if (alg == COSE_ES256) {
		EC_KEY *alt = NULL;

		if ((kc->ec = es256_key_new(resign_es256_sk)) == NULL ||
		    (alt = es256_key_new(resign_es256_alt_sk)) == NULL ||
		    es256_pubkey(kc->ec, &kc->es256_pk) < 0 ||
		    es256_pubkey(alt, &kc->es256_alt) < 0) {
			EC_KEY_free(alt);
			return -1;
		}
		EC_KEY_free(alt);
	} else {
		EVP_PKEY *alt = NULL;

		if ((kc->ed = eddsa_key_new(resign_eddsa_sk)) == NULL ||
		    (alt = eddsa_key_new(resign_eddsa_alt_sk)) == NULL ||
		    eddsa_pubkey(kc->ed, &kc->eddsa_pk) < 0 ||
		    eddsa_pubkey(alt, &kc->eddsa_alt) < 0) {
			EVP_PKEY_free(alt);
			return -1;
		}
		EVP_PKEY_free(alt);
	}

	return 0;
}

static void
keyctx_free(struct keyctx *kc)
{
	EC_KEY_free(kc->ec);
	EVP_PKEY_free(kc->ed);
}

static int
keyctx_sign(const struct keyctx *kc, const uint8_t *nonce,
    const uint8_t *msg, size_t msg_len, uint8_t *out, size_t *out_len)
{
	uint8_t dgst[SHA256_DIGEST_LENGTH];

	if (kc->alg == COSE_ES256) {
		if (SHA256(msg, msg_len, dgst) == NULL)
			return -1;
		return es256_sign(kc->ec, nonce, dgst, out, out_len);
	}

	return eddsa_sign(kc->ed, msg, msg_len, out, out_len);
}

static const void *
keyctx_pk(const struct keyctx *kc)
{
	return kc->alg == COSE_ES256 ?
	    (const void *)&kc->es256_pk : (const void *)&kc->eddsa_pk;
}

static const void *
keyctx_alt_pk(const struct keyctx *kc)
{
	return kc->alg == COSE_ES256 ?
	    (const void *)&kc->es256_alt : (const void *)&kc->eddsa_alt;
}

/*
 * Re-encode an ECDSA DER signature. With pad=0 this is a canonical
 * decode/encode round-trip; with pad=1 the r INTEGER gets a non-minimal
 * leading zero, i.e. a different encoding of the same (r, s) material.
 */
static size_t
der_int_tlv(const BIGNUM *v, int pad, uint8_t *out, size_t out_len)
{
	uint8_t body[40];
	size_t n;

	if ((n = (size_t)BN_num_bytes(v)) > 32)
		return 0;
	if (BN_bn2bin(v, body) < 0)
		return 0;
	if (body[0] & 0x80) {
		/* canonical sign pad */
		memmove(body + 1, body, n);
		body[0] = 0;
		n++;
	}
	if (pad) {
		/* non-minimal leading zero */
		memmove(body + 1, body, n);
		body[0] = 0;
		n++;
	}
	if (n > 127 || 2 + n > out_len)
		return 0;

	out[0] = 0x02;
	out[1] = (uint8_t)n;
	memcpy(out + 2, body, n);

	return 2 + n;
}

static size_t
reencode_es256_sig(const uint8_t *in, size_t in_len, int pad, uint8_t *out,
    size_t out_len)
{
	const uint8_t *p = in;
	ECDSA_SIG *s = NULL;
	uint8_t rt[40], st[40];
	size_t rn, sn, total = 0;

	if ((s = d2i_ECDSA_SIG(NULL, &p, (long)in_len)) == NULL)
		goto out;
	if ((rn = der_int_tlv(ECDSA_SIG_get0_r(s), pad, rt,
	    sizeof(rt))) == 0)
		goto out;
	if ((sn = der_int_tlv(ECDSA_SIG_get0_s(s), 0, st,
	    sizeof(st))) == 0)
		goto out;
	if (rn + sn > 127 || 2 + rn + sn > out_len)
		goto out;

	out[0] = 0x30;
	out[1] = (uint8_t)(rn + sn);
	memcpy(out + 2, rt, rn);
	memcpy(out + 2 + rn, st, sn);
	total = 2 + rn + sn;
out:
	if (s)
		ECDSA_SIG_free(s);

	return total;
}


/* do two DER encodings decode to the same (r, s) material? */
static int
same_es256_material(const uint8_t *a, size_t a_len, const uint8_t *b,
    size_t b_len)
{
	const uint8_t *pa = a, *pb = b;
	ECDSA_SIG *sa = NULL, *sb = NULL;
	int same = 0;

	sa = d2i_ECDSA_SIG(NULL, &pa, (long)a_len);
	sb = d2i_ECDSA_SIG(NULL, &pb, (long)b_len);
	if (sa != NULL && sb != NULL &&
	    BN_cmp(ECDSA_SIG_get0_r(sa), ECDSA_SIG_get0_r(sb)) == 0 &&
	    BN_cmp(ECDSA_SIG_get0_s(sa), ECDSA_SIG_get0_s(sb)) == 0)
		same = 1;
	if (sa != NULL)
		ECDSA_SIG_free(sa);
	if (sb != NULL)
		ECDSA_SIG_free(sb);

	return same;
}

/* Build rpIdHash || flags || signCount [ || attested credential data ]. */
static size_t
build_authdata(uint8_t *out, size_t out_len, const char *rp_id,
    uint8_t flags, uint32_t sigcount, const uint8_t *cred_id,
    size_t cred_id_len, const uint8_t *cose, size_t cose_len)
{
	uint8_t rph[SHA256_DIGEST_LENGTH];
	size_t o = 0, tail = 0;

	if (cred_id != NULL)
		tail = 16 + 2 + cred_id_len + cose_len;
	if (out_len < 37 + tail)
		return 0;
	if (SHA256((const uint8_t *)rp_id, strlen(rp_id), rph) == NULL)
		return 0;

	memcpy(out + o, rph, sizeof(rph));
	o += sizeof(rph);
	out[o++] = flags;
	out[o++] = (uint8_t)(sigcount >> 24);
	out[o++] = (uint8_t)(sigcount >> 16);
	out[o++] = (uint8_t)(sigcount >> 8);
	out[o++] = (uint8_t)(sigcount);

	if (cred_id != NULL) {
		memset(out + o, 0, 16); /* aaguid */
		o += 16;
		out[o++] = (uint8_t)(cred_id_len >> 8);
		out[o++] = (uint8_t)(cred_id_len);
		memcpy(out + o, cred_id, cred_id_len);
		o += cred_id_len;
		memcpy(out + o, cose, cose_len);
		o += cose_len;
	}

	return o;
}

static uint8_t *
cose_key_es256(const es256_pk_t *pk, size_t *out_len)
{
	struct cbor_pair pairs[5];
	cbor_item_t *map = NULL;
	uint8_t *out = NULL;
	size_t alloc_len = 0, len;
	int ok = -1;

	memset(pairs, 0, sizeof(pairs));

	if ((map = cbor_new_definite_map(5)) == NULL ||
	    (pairs[0].key = cbor_build_uint8(1)) == NULL ||
	    (pairs[0].value = cbor_build_uint8(2)) == NULL ||
	    (pairs[1].key = cbor_build_uint8(3)) == NULL ||
	    (pairs[1].value = cbor_build_negint8(6)) == NULL ||
	    (pairs[2].key = cbor_build_negint8(0)) == NULL ||
	    (pairs[2].value = cbor_build_uint8(1)) == NULL ||
	    (pairs[3].key = cbor_build_negint8(1)) == NULL ||
	    (pairs[3].value = cbor_build_bytestring(pk->x,
		sizeof(pk->x))) == NULL ||
	    (pairs[4].key = cbor_build_negint8(2)) == NULL ||
	    (pairs[4].value = cbor_build_bytestring(pk->y,
		sizeof(pk->y))) == NULL)
		goto out;

	for (size_t i = 0; i < 5; i++)
		if (cbor_map_add(map, pairs[i]) == false)
			goto out;

	if ((len = cbor_serialize_alloc(map, &out, &alloc_len)) == 0) {
		out = NULL;
		goto out;
	}

	*out_len = len;
	ok = 0;
out:
	for (size_t i = 0; i < 5; i++) {
		if (pairs[i].key)
			cbor_decref(&pairs[i].key);
		if (pairs[i].value)
			cbor_decref(&pairs[i].value);
	}

	if (map)
		cbor_decref(&map);

	if (ok < 0) {
		free(out);
		out = NULL;
	}

	return out;
}

static uint8_t *
cose_key_eddsa(const eddsa_pk_t *pk, size_t *out_len)
{
	struct cbor_pair pairs[4];
	cbor_item_t *map = NULL;
	uint8_t *out = NULL;
	size_t alloc_len = 0, len;
	int ok = -1;

	memset(pairs, 0, sizeof(pairs));

	if ((map = cbor_new_definite_map(4)) == NULL ||
	    (pairs[0].key = cbor_build_uint8(1)) == NULL ||
	    (pairs[0].value = cbor_build_uint8(1)) == NULL ||
	    (pairs[1].key = cbor_build_uint8(3)) == NULL ||
	    (pairs[1].value = cbor_build_negint8(7)) == NULL ||
	    (pairs[2].key = cbor_build_negint8(0)) == NULL ||
	    (pairs[2].value = cbor_build_uint8(6)) == NULL ||
	    (pairs[3].key = cbor_build_negint8(1)) == NULL ||
	    (pairs[3].value = cbor_build_bytestring(pk->x,
		sizeof(pk->x))) == NULL)
		goto out;

	for (size_t i = 0; i < 4; i++)
		if (cbor_map_add(map, pairs[i]) == false)
			goto out;

	if ((len = cbor_serialize_alloc(map, &out, &alloc_len)) == 0) {
		out = NULL;
		goto out;
	}

	*out_len = len;
	ok = 0;
out:
	for (size_t i = 0; i < 4; i++) {
		if (pairs[i].key)
			cbor_decref(&pairs[i].key);
		if (pairs[i].value)
			cbor_decref(&pairs[i].value);
	}

	if (map)
		cbor_decref(&map);

	if (ok < 0) {
		free(out);
		out = NULL;
	}

	return out;
}

static uint8_t *
cose_key(const struct keyctx *kc, int alt, size_t *out_len)
{
	if (kc->alg == COSE_ES256)
		return cose_key_es256(alt ? &kc->es256_alt : &kc->es256_pk,
		    out_len);

	return cose_key_eddsa(alt ? &kc->eddsa_alt : &kc->eddsa_pk, out_len);
}

/* Bounded copy of a fuzzable blob, falling back to a fixed default. */
static size_t
bounded_blob(uint8_t *out, size_t out_len, const struct blob *b,
    const uint8_t *dfl, size_t dfl_len)
{
	size_t n = b->len;

	if (n == 0) {
		memcpy(out, dfl, dfl_len);
		return dfl_len;
	}

	if (n > out_len)
		n = out_len;
	memcpy(out, b->body, n);

	return n;
}

/*
 * Custom-I/O round-trip: drive fido_dev_get_assert() over an emulated
 * transport and re-verify whatever the emulated authenticator returned.
 */
static void
device_assert(const struct param *p)
{
	fido_dev_t *dev = NULL;
	fido_assert_t *assert = NULL;
	es256_pk_t *pk = NULL;
	uint8_t flags;
	uint32_t sigcount;
	int r;

	if ((dev = open_dev(p->opt & OPT_NFC)) == NULL)
		return;
	if ((assert = fido_assert_new()) == NULL)
		goto out;

	set_wire_data(p->wire_data.body, p->wire_data.len);

	fido_assert_set_clientdata_hash(assert, p->cdh.body, p->cdh.len);
	fido_assert_set_rp(assert, p->rp_id);
	if (p->up & 1)
		fido_assert_set_up(assert, FIDO_OPT_TRUE);
	if (p->uv & 1)
		fido_assert_set_uv(assert, FIDO_OPT_TRUE);
	fido_assert_allow_cred(assert, p->cred.body, p->cred.len);

	fido_dev_get_assert(dev, assert, NULL);

	if ((pk = es256_pk_new()) != NULL &&
	    es256_pk_from_ptr(pk, p->pk.body, p->pk.len) == FIDO_OK) {
		for (size_t i = 0; i < fido_assert_count(assert); i++) {
			r = fido_assert_verify(assert, i, COSE_ES256, pk);
			consume(&r, sizeof(r));
		}
	}

	for (size_t i = 0; i < fido_assert_count(assert); i++) {
		consume(fido_assert_authdata_ptr(assert, i),
		    fido_assert_authdata_len(assert, i));
		consume(fido_assert_id_ptr(assert, i),
		    fido_assert_id_len(assert, i));
		consume(fido_assert_sig_ptr(assert, i),
		    fido_assert_sig_len(assert, i));
		flags = fido_assert_flags(assert, i);
		consume(&flags, sizeof(flags));
		sigcount = fido_assert_sigcount(assert, i);
		consume(&sigcount, sizeof(sigcount));
	}
out:
	es256_pk_free(&pk);
	fido_assert_free(&assert);

	fido_dev_cancel(dev);
	fido_dev_close(dev);
	fido_dev_free(&dev);
}

/*
 * Re-signed assertion: sign canonical authenticator data with the
 * harness key and check the verification invariants.
 */
static void
resign_assert(const struct param *p, const struct keyctx *kc)
{
	fido_assert_t *a = NULL;
	es256_pk_t *pk1 = NULL;
	es384_pk_t *es384 = NULL;
	rs256_pk_t *rs256 = NULL;
	eddsa_pk_t *eddsa1 = NULL;
	cbor_item_t *item = NULL;
	uint8_t authdata[37];
	uint8_t msg[sizeof(authdata) + MAXCDH];
	uint8_t cdh[MAXCDH];
	uint8_t cdh1[MAXCDH];
	uint8_t nonce[32];
	uint8_t sig0[MAXSIG];
	uint8_t sig1[MAXSIG + 2];
	uint8_t *cbor = NULL;
	size_t cdh_len, sig0_len = 0, sig1_len, cbor_len, cbor_alloc;
	size_t msg_len;
	uint8_t flags;
	int ext, r;

	cdh_len = bounded_blob(cdh, sizeof(cdh), &p->cdh, resign_cdh,
	    sizeof(resign_cdh));

	flags = 0;
	if (p->up & 1)
		flags |= CTAP_AUTHDATA_USER_PRESENT;
	if (p->uv & 1)
		flags |= CTAP_AUTHDATA_USER_VERIFIED;

	if (build_authdata(authdata, sizeof(authdata), p->rp_id, flags,
	    (uint32_t)p->seed, NULL, 0, NULL, 0) != sizeof(authdata))
		goto out;

	memcpy(msg, authdata, sizeof(authdata));
	memcpy(msg + sizeof(authdata), cdh, cdh_len);
	msg_len = sizeof(authdata) + cdh_len;

	prng_bytes(nonce, sizeof(nonce));

	if (keyctx_sign(kc, nonce, msg, msg_len, sig0, &sig0_len) < 0)
		goto out;

	if ((a = fido_assert_new()) == NULL)
		goto out;
	if (fido_assert_set_clientdata_hash(a, cdh, cdh_len) != FIDO_OK ||
	    fido_assert_set_rp(a, p->rp_id) != FIDO_OK ||
	    fido_assert_set_count(a, 1) != FIDO_OK ||
	    fido_assert_set_authdata_raw(a, 0, authdata,
		sizeof(authdata)) != FIDO_OK ||
	    fido_assert_set_sig(a, 0, sig0, sig0_len) != FIDO_OK)
		goto out;
	fido_assert_set_up(a, (p->up & 1) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
	fido_assert_set_uv(a, (p->uv & 1) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);

	r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
	consume(&r, sizeof(r));
	if (r != FIDO_OK)
		goto out; /* failure injection; invariants not applicable */

	/*
	 * UP/UV: requiring a property the authenticator data does not
	 * attest must never succeed.
	 */
	fido_assert_set_up(a, FIDO_OPT_TRUE);
	fido_assert_set_uv(a, FIDO_OPT_TRUE);
	r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
	consume(&r, sizeof(r));
	if ((p->up & 1) == 0 || (p->uv & 1) == 0)
		INVARIANT(r == FIDO_ERR_INVALID_PARAM);
	else
		INVARIANT(r == FIDO_OK);
	fido_assert_set_up(a, (p->up & 1) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
	fido_assert_set_uv(a, (p->uv & 1) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);

	/*
	 * Extensions: the authenticator data attests none; requiring one
	 * must never succeed.
	 */
	ext = p->ext & (FIDO_EXT_HMAC_SECRET | FIDO_EXT_CRED_BLOB |
	    FIDO_EXT_PAYMENT);
	fido_assert_set_extensions(a, ext);
	r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
	consume(&r, sizeof(r));
	if (ext != 0)
		INVARIANT(r == FIDO_ERR_INVALID_PARAM);
	else
		INVARIANT(r == FIDO_OK);
	fido_assert_set_extensions(a, 0);

	/*
	 * Re-encoding: the same signature material, re-serialised, must
	 * produce the same verdict.
	 */
	if (kc->alg == COSE_ES256) {
		/* canonical DER round-trip */
		if ((sig1_len = reencode_es256_sig(sig0, sig0_len, 0, sig1,
		    sizeof(sig1))) != 0 &&
		    fido_assert_set_sig(a, 0, sig1, sig1_len) == FIDO_OK) {
			r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
			consume(&r, sizeof(r));
			INVARIANT(r == FIDO_OK);
		}
		/*
		 * non-minimal DER encoding of the same (r, s): the
		 * verdict must remain FIDO_OK if the decoder accepts
		 * the padding, and must not become an erroneous pass
		 * if it does not.
		 */
		if ((sig1_len = reencode_es256_sig(sig0, sig0_len, 1, sig1,
		    sizeof(sig1))) != 0 &&
		    fido_assert_set_sig(a, 0, sig1, sig1_len) == FIDO_OK) {
			r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
			consume(&r, sizeof(r));
			if (same_es256_material(sig0, sig0_len, sig1,
			    sig1_len))
				INVARIANT(r == FIDO_OK);
			else
				INVARIANT(r != FIDO_OK);
		}
		if (fido_assert_set_sig(a, 0, sig0, sig0_len) != FIDO_OK)
			goto out;
	}

	/* CBOR re-serialisation of the authdata container */
	if ((item = cbor_build_bytestring(authdata,
	    sizeof(authdata))) != NULL) {
		if ((cbor_len = cbor_serialize_alloc(item, &cbor,
		    &cbor_alloc)) != 0 &&
		    fido_assert_set_authdata(a, 0, cbor,
			cbor_len) == FIDO_OK) {
			r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
			consume(&r, sizeof(r));
			INVARIANT(r == FIDO_OK);
		}
		cbor_decref(&item);
		item = NULL;
		free(cbor);
		cbor = NULL;
		if (fido_assert_set_authdata_raw(a, 0, authdata,
		    sizeof(authdata)) != FIDO_OK)
			goto out;
	}

	/*
	 * Public key substitution must never succeed, neither with a
	 * different key of the same algorithm nor through algorithm
	 * confusion.
	 */
	r = fido_assert_verify(a, 0, kc->alg, keyctx_alt_pk(kc));
	consume(&r, sizeof(r));
	INVARIANT(r != FIDO_OK);

	if (kc->alg == COSE_ES256) {
		if ((pk1 = es256_pk_new()) != NULL &&
		    es256_pk_from_ptr(pk1, p->pk.body,
			p->pk.len) == FIDO_OK &&
		    memcmp(pk1, &kc->es256_pk, sizeof(*pk1)) != 0) {
			r = fido_assert_verify(a, 0, kc->alg, pk1);
			consume(&r, sizeof(r));
			INVARIANT(r != FIDO_OK);
		}
	} else {
		if ((eddsa1 = eddsa_pk_new()) != NULL &&
		    eddsa_pk_from_ptr(eddsa1, p->pk.body,
			p->pk.len) == FIDO_OK &&
		    memcmp(eddsa1, &kc->eddsa_pk, sizeof(*eddsa1)) != 0) {
			r = fido_assert_verify(a, 0, kc->alg, eddsa1);
			consume(&r, sizeof(r));
			INVARIANT(r != FIDO_OK);
		}
	}

	if ((es384 = es384_pk_new()) != NULL &&
	    es384_pk_from_ptr(es384, p->pk.body, p->pk.len) == FIDO_OK) {
		r = fido_assert_verify(a, 0, COSE_ES384, es384);
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
	}
	if ((rs256 = rs256_pk_new()) != NULL &&
	    rs256_pk_from_ptr(rs256, p->pk.body, p->pk.len) == FIDO_OK) {
		r = fido_assert_verify(a, 0, COSE_RS256, rs256);
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
	}

	/*
	 * An attacker-supplied signature must never succeed.
	 */
	if (p->sig.len != 0 &&
	    (p->sig.len != sig0_len || memcmp(p->sig.body, sig0,
		sig0_len) != 0) &&
	    fido_assert_set_sig(a, 0, p->sig.body, p->sig.len) == FIDO_OK) {
		r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
		if (fido_assert_set_sig(a, 0, sig0, sig0_len) != FIDO_OK)
			goto out;
	}

	/*
	 * Client data hash substitution must never succeed.
	 */
	memcpy(cdh1, cdh, cdh_len);
	cdh1[0] ^= 1;
	if (fido_assert_set_clientdata_hash(a, cdh1, cdh_len) == FIDO_OK) {
		r = fido_assert_verify(a, 0, kc->alg, keyctx_pk(kc));
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
	}
out:
	es256_pk_free(&pk1);
	es384_pk_free(&es384);
	rs256_pk_free(&rs256);
	if (eddsa1)
		eddsa_pk_free(&eddsa1);
	if (item)
		cbor_decref(&item);
	free(cbor);
	fido_assert_free(&a);
}

/*
 * Re-signed self-attestation: build attested credential data around the
 * harness public key, sign it, and check the fido_cred_verify_self()
 * invariants.
 */
static void
resign_selfattest(const struct param *p, const struct keyctx *kc)
{
	fido_cred_t *cred = NULL;
	uint8_t *cose = NULL, *cose_alt = NULL;
	uint8_t authdata[512];
	uint8_t msg[1024];
	uint8_t cdh[MAXCDH];
	uint8_t cred_id[MAXCRED];
	uint8_t nonce[32];
	uint8_t sig0[MAXSIG];
	uint8_t sig1[MAXSIG + 2];
	size_t cdh_len, cred_id_len, cose_len = 0, cose_alt_len = 0;
	size_t authdata_len, msg_len = 0, sig0_len = 0, sig1_len;
	uint8_t flags;
	const char *fmt;
	int u2f_fmt, r;

	cdh_len = bounded_blob(cdh, sizeof(cdh), &p->cdh, resign_cdh,
	    sizeof(resign_cdh));
	cred_id_len = bounded_blob(cred_id, sizeof(cred_id), &p->cred,
	    resign_cred_id, sizeof(resign_cred_id));

	u2f_fmt = (p->opt & OPT_U2F_FMT) && kc->alg == COSE_ES256;
	fmt = u2f_fmt ? "fido-u2f" : "packed";

	if ((cose = cose_key(kc, 0, &cose_len)) == NULL ||
	    (cose_alt = cose_key(kc, 1, &cose_alt_len)) == NULL)
		goto out;

	flags = CTAP_AUTHDATA_USER_PRESENT | CTAP_AUTHDATA_ATT_CRED;
	if (p->uv & 1)
		flags |= CTAP_AUTHDATA_USER_VERIFIED;

	if ((authdata_len = build_authdata(authdata, sizeof(authdata),
	    p->rp_id, flags, (uint32_t)p->seed, cred_id, cred_id_len, cose,
	    cose_len)) == 0)
		goto out;

	if (u2f_fmt) {
		/* 0x00 || rpIdHash || cdh || credId || 0x04 || x || y */
		uint8_t rph[SHA256_DIGEST_LENGTH];
		size_t o = 0;

		if (SHA256((const uint8_t *)p->rp_id, strlen(p->rp_id),
		    rph) == NULL)
			goto out;
		msg[o++] = 0;
		memcpy(msg + o, rph, sizeof(rph));
		o += sizeof(rph);
		memcpy(msg + o, cdh, cdh_len);
		o += cdh_len;
		memcpy(msg + o, cred_id, cred_id_len);
		o += cred_id_len;
		msg[o++] = 4; /* uncompressed point */
		memcpy(msg + o, kc->es256_pk.x, sizeof(kc->es256_pk.x));
		o += sizeof(kc->es256_pk.x);
		memcpy(msg + o, kc->es256_pk.y, sizeof(kc->es256_pk.y));
		o += sizeof(kc->es256_pk.y);
		msg_len = o;
	} else {
		/* authdata || cdh */
		memcpy(msg, authdata, authdata_len);
		memcpy(msg + authdata_len, cdh, cdh_len);
		msg_len = authdata_len + cdh_len;
	}

	prng_bytes(nonce, sizeof(nonce));

	if (keyctx_sign(kc, nonce, msg, msg_len, sig0, &sig0_len) < 0)
		goto out;

	if ((cred = fido_cred_new()) == NULL)
		goto out;
	if (fido_cred_set_type(cred, kc->alg) != FIDO_OK ||
	    fido_cred_set_clientdata_hash(cred, cdh, cdh_len) != FIDO_OK ||
	    fido_cred_set_rp(cred, p->rp_id, NULL) != FIDO_OK ||
	    fido_cred_set_authdata_raw(cred, authdata,
		authdata_len) != FIDO_OK ||
	    fido_cred_set_fmt(cred, fmt) != FIDO_OK ||
	    fido_cred_set_sig(cred, sig0, sig0_len) != FIDO_OK)
		goto out;
	fido_cred_set_uv(cred, (p->uv & 1) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);

	r = fido_cred_verify_self(cred);
	consume(&r, sizeof(r));
	if (r != FIDO_OK)
		goto out; /* failure injection; invariants not applicable */

	/*
	 * Re-encoding: the same signature material, re-serialised, must
	 * produce the same verdict.
	 */
	if (kc->alg == COSE_ES256) {
		if ((sig1_len = reencode_es256_sig(sig0, sig0_len, 0, sig1,
		    sizeof(sig1))) != 0 &&
		    fido_cred_set_sig(cred, sig1, sig1_len) == FIDO_OK) {
			r = fido_cred_verify_self(cred);
			consume(&r, sizeof(r));
			INVARIANT(r == FIDO_OK);
		}
		if ((sig1_len = reencode_es256_sig(sig0, sig0_len, 1, sig1,
		    sizeof(sig1))) != 0 &&
		    fido_cred_set_sig(cred, sig1, sig1_len) == FIDO_OK) {
			r = fido_cred_verify_self(cred);
			consume(&r, sizeof(r));
			if (same_es256_material(sig0, sig0_len, sig1,
			    sig1_len))
				INVARIANT(r == FIDO_OK);
			else
				INVARIANT(r != FIDO_OK);
		}
		if (fido_cred_set_sig(cred, sig0, sig0_len) != FIDO_OK)
			goto out;
	}

	/*
	 * UV: requiring verification the authenticator data does not
	 * attest must never succeed. UP is unconditionally required by
	 * fido_cred_verify_self() and always set above.
	 */
	fido_cred_set_uv(cred, FIDO_OPT_TRUE);
	r = fido_cred_verify_self(cred);
	consume(&r, sizeof(r));
	if ((p->uv & 1) == 0)
		INVARIANT(r == FIDO_ERR_INVALID_PARAM);
	else
		INVARIANT(r == FIDO_OK);
	fido_cred_set_uv(cred, (p->uv & 1) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);

	/*
	 * Credential ID substitution must never succeed: the ID is
	 * covered by the attestation signature.
	 */
	cred_id[0] ^= 1;
	if ((authdata_len = build_authdata(authdata, sizeof(authdata),
	    p->rp_id, flags, (uint32_t)p->seed, cred_id, cred_id_len, cose,
	    cose_len)) != 0 &&
	    fido_cred_set_authdata_raw(cred, authdata,
		authdata_len) == FIDO_OK) {
		r = fido_cred_verify_self(cred);
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
	}
	cred_id[0] ^= 1;

	/*
	 * Public key substitution must never succeed: the replacement
	 * key in the attested credential data is not the key that
	 * produced the attestation signature.
	 */
	if ((authdata_len = build_authdata(authdata, sizeof(authdata),
	    p->rp_id, flags, (uint32_t)p->seed, cred_id, cred_id_len,
	    cose_alt, cose_alt_len)) != 0 &&
	    fido_cred_set_authdata_raw(cred, authdata,
		authdata_len) == FIDO_OK) {
		r = fido_cred_verify_self(cred);
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
	}

	/* restore the original authdata */
	if ((authdata_len = build_authdata(authdata, sizeof(authdata),
	    p->rp_id, flags, (uint32_t)p->seed, cred_id, cred_id_len, cose,
	    cose_len)) == 0 ||
	    fido_cred_set_authdata_raw(cred, authdata,
		authdata_len) != FIDO_OK)
		goto out;

	/*
	 * Client data hash substitution must never succeed.
	 */
	cdh[0] ^= 1;
	if (fido_cred_set_clientdata_hash(cred, cdh, cdh_len) == FIDO_OK) {
		r = fido_cred_verify_self(cred);
		consume(&r, sizeof(r));
		INVARIANT(r != FIDO_OK);
	}
	cdh[0] ^= 1;
	if (fido_cred_set_clientdata_hash(cred, cdh, cdh_len) != FIDO_OK)
		goto out;

	/*
	 * Self-attestation semantics: an x5c chain must not be present.
	 */
	if (fido_cred_set_x509(cred, sig0, sig0_len) == FIDO_OK) {
		r = fido_cred_verify_self(cred);
		consume(&r, sizeof(r));
		INVARIANT(r == FIDO_ERR_INVALID_ARGUMENT);
	}
out:
	free(cose);
	free(cose_alt);
	fido_cred_free(&cred);
}

void
test(const struct param *p)
{
	struct keyctx kc;

	prng_init((unsigned int)p->seed);
	fuzz_clock_reset();
	fido_init(FIDO_DEBUG);
	fido_set_log_handler(consume_str);

	if (p->opt & OPT_DEVICE)
		device_assert(p);

	if (keyctx_init(&kc, (p->type & 1) ? COSE_EDDSA : COSE_ES256) < 0)
		return;

	resign_assert(p, &kc);

	if (p->opt & OPT_SELF)
		resign_selfattest(p, &kc);

	keyctx_free(&kc);
}

void
cross_over(struct param *p1, const struct param *p2, unsigned int seed,
    unsigned int flags) NO_MSAN
{
	if (flags & MUTATE_SEED)
		cross_int(&p1->seed, &p2->seed, &seed);

	if (flags & MUTATE_PARAM) {
		cross_byte(&p1->uv, &p2->uv, &seed);
		cross_byte(&p1->up, &p2->up, &seed);
		cross_byte(&p1->opt, &p2->opt, &seed);
		cross_byte(&p1->type, &p2->type, &seed);
		cross_int(&p1->ext, &p2->ext, &seed);
		cross_blob(&p1->cdh, &p2->cdh, &seed);
		cross_blob(&p1->cred, &p2->cred, &seed);
		cross_blob(&p1->sig, &p2->sig, &seed);
		cross_blob(&p1->pk, &p2->pk, &seed);
		cross_string(p1->rp_id, p2->rp_id, &seed);
	}

	if (flags & MUTATE_WIREDATA)
		cross_blob(&p1->wire_data, &p2->wire_data, &seed);
}

void
mutate(struct param *p, unsigned int seed, unsigned int flags) NO_MSAN
{
	if (flags & MUTATE_SEED)
		p->seed = (int)seed;

	if (flags & MUTATE_PARAM) {
		mutate_byte(&p->uv);
		mutate_byte(&p->up);
		mutate_byte(&p->opt);
		mutate_byte(&p->type);
		mutate_int(&p->ext);
		mutate_blob(&p->cdh);
		mutate_blob(&p->cred);
		mutate_blob(&p->sig);
		mutate_blob(&p->pk);
		mutate_string(p->rp_id);

		p->opt &= OPT_MASK;
	}

	if (flags & MUTATE_WIREDATA)
		mutate_blob(&p->wire_data);
}
