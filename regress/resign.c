/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * CTest regression for the re-signing assertion/self-attestation fuzz
 * harness (fuzz/fuzz_resign.c). Each test is a minimal, deterministic
 * sample covering one security invariant of fido_assert_verify() and
 * fido_cred_verify_self():
 *
 * - re-encoding the same signature material (DER round-trip, non-minimal
 *   DER, CBOR re-serialisation of the authdata container) must not change
 *   the verification verdict;
 * - substituting the public key (including algorithm confusion) must
 *   never yield FIDO_OK;
 * - substituting the signature, the client data hash, or the credential
 *   ID must never yield FIDO_OK;
 * - requiring UP/UV flags or extensions that the authenticator data does
 *   not attest must never yield FIDO_OK;
 * - self-attestation must not carry an x5c certificate chain.
 *
 * Key material is fixed and test-only (fuzz/resign_vectors.h); ECDSA
 * uses a fixed nonce and Ed25519 is deterministic by construction, so
 * every signature in this file is reproducible. The device round-trip
 * test uses custom I/O functions (regress/mock.c) talking to a scripted
 * HID authenticator whose getAssertion response is built (and re-signed)
 * at runtime.
 */

#undef NDEBUG

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

#define _FIDO_INTERNAL

#include <fido.h>
#include <fido/es256.h>
#include <fido/es384.h>
#include <fido/rs256.h>
#include <fido/eddsa.h>

#include "extern.h"
#include "../fuzz/wiredata_fido2.h"
#include "../fuzz/resign_vectors.h"

static EC_KEY *
es256_key_new(const uint8_t *sk)
{
	const EC_GROUP *g;
	EC_KEY *ec = NULL;
	EC_POINT *q = NULL;
	BIGNUM *d = NULL;

	ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	assert(ec != NULL);
	d = BN_bin2bn(sk, 32, NULL);
	assert(d != NULL);
	g = EC_KEY_get0_group(ec);
	assert(g != NULL);
	q = EC_POINT_new(g);
	assert(q != NULL);
	assert(EC_POINT_mul(g, q, d, NULL, NULL, NULL) == 1);
	assert(EC_KEY_set_private_key(ec, d) == 1);
	assert(EC_KEY_set_public_key(ec, q) == 1);

	BN_free(d);
	EC_POINT_free(q);

	return ec;
}

static void
es256_pubkey(const EC_KEY *ec, es256_pk_t *pk)
{
	const EC_GROUP *g;
	const EC_POINT *q;
	BIGNUM *x = NULL, *y = NULL;
	uint8_t xy[64];

	g = EC_KEY_get0_group(ec);
	assert(g != NULL);
	q = EC_KEY_get0_public_key(ec);
	assert(q != NULL);
	x = BN_new();
	y = BN_new();
	assert(x != NULL && y != NULL);
	assert(EC_POINT_get_affine_coordinates_GFp(g, q, x, y, NULL) == 1);
	assert(BN_bn2binpad(x, xy, 32) == 32);
	assert(BN_bn2binpad(y, xy + 32, 32) == 32);
	assert(es256_pk_from_ptr(pk, xy, sizeof(xy)) == FIDO_OK);

	BN_free(x);
	BN_free(y);
}

/* derive a valid P-384 public key from a fixed scalar */
static void
es384_pubkey_derive(const uint8_t *sk, es384_pk_t *pk)
{
	const EC_GROUP *g;
	EC_KEY *ec = NULL;
	EC_POINT *q = NULL;
	BN_CTX *bnctx = NULL;
	BIGNUM *d = NULL, *x = NULL, *y = NULL;
	uint8_t xy[96];

	ec = EC_KEY_new_by_curve_name(NID_secp384r1);
	assert(ec != NULL);
	d = BN_bin2bn(sk, 32, NULL);
	bnctx = BN_CTX_new();
	x = BN_new();
	y = BN_new();
	assert(d != NULL && bnctx != NULL && x != NULL && y != NULL);
	g = EC_KEY_get0_group(ec);
	assert(g != NULL);
	q = EC_POINT_new(g);
	assert(q != NULL);
	assert(EC_POINT_mul(g, q, d, NULL, NULL, bnctx) == 1);
	assert(EC_POINT_get_affine_coordinates_GFp(g, q, x, y, bnctx) == 1);
	assert(BN_bn2binpad(x, xy, 48) == 48);
	assert(BN_bn2binpad(y, xy + 48, 48) == 48);
	assert(es384_pk_from_ptr(pk, xy, sizeof(xy)) == FIDO_OK);

	BN_free(d);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bnctx);
	EC_POINT_free(q);
	EC_KEY_free(ec);
}

/* deterministic ECDSA over P-256 using resign_es256_nonce as k */
static size_t
es256_sign(EC_KEY *ec, const uint8_t *dgst, uint8_t *out)
{
	const EC_GROUP *g;
	EC_POINT *pt = NULL;
	BN_CTX *bnctx = NULL;
	BIGNUM *k = NULL, *kinv = NULL, *r = NULL, *order = NULL, *x = NULL;
	unsigned int len = 0;

	g = EC_KEY_get0_group(ec);
	assert(g != NULL);
	bnctx = BN_CTX_new();
	order = BN_new();
	k = BN_bin2bn(resign_es256_nonce, sizeof(resign_es256_nonce), NULL);
	kinv = BN_new();
	r = BN_new();
	x = BN_new();
	assert(bnctx != NULL && order != NULL && k != NULL && kinv != NULL &&
	    r != NULL && x != NULL);
	assert(EC_GROUP_get_order(g, order, bnctx) == 1);
	assert(BN_nnmod(k, k, order, bnctx) == 1);
	assert(!BN_is_zero(k));
	pt = EC_POINT_new(g);
	assert(pt != NULL);
	assert(EC_POINT_mul(g, pt, k, NULL, NULL, bnctx) == 1);
	assert(EC_POINT_get_affine_coordinates_GFp(g, pt, x, NULL,
	    bnctx) == 1);
	assert(BN_nnmod(r, x, order, bnctx) == 1);
	assert(!BN_is_zero(r));
	assert(BN_mod_inverse(kinv, k, order, bnctx) != NULL);
	assert(ECDSA_sign_ex(0, dgst, SHA256_DIGEST_LENGTH, out, &len, kinv,
	    r, ec) == 1);

	BN_free(k);
	BN_free(kinv);
	BN_free(r);
	BN_free(order);
	BN_free(x);
	BN_CTX_free(bnctx);
	EC_POINT_free(pt);

	return len;
}

static EVP_PKEY *
eddsa_key_new(const uint8_t *sk)
{
	EVP_PKEY *pkey;

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
	assert(pkey != NULL);

	return pkey;
}

static void
eddsa_pubkey(const EVP_PKEY *sk, eddsa_pk_t *pk)
{
	uint8_t x[32];
	size_t len = sizeof(x);

	assert(EVP_PKEY_get_raw_public_key(sk, x, &len) == 1);
	assert(len == sizeof(x));
	assert(eddsa_pk_from_ptr(pk, x, sizeof(x)) == FIDO_OK);
}

static size_t
eddsa_sign(EVP_PKEY *sk, const uint8_t *msg, size_t msg_len,
    uint8_t *out)
{
	EVP_MD_CTX *ctx = NULL;
	size_t len = 64;

	ctx = EVP_MD_CTX_new();
	assert(ctx != NULL);
	assert(EVP_DigestSignInit(ctx, NULL, NULL, NULL,
	    sk) == 1);
	assert(EVP_DigestSign(ctx, out, &len, msg, msg_len) == 1);

	EVP_MD_CTX_free(ctx);

	return len;
}

/* rpIdHash || flags || signCount [ || aaguid || idLen || id || coseKey ] */
static size_t
build_authdata(uint8_t *out, const char *rp_id, uint8_t flags,
    uint32_t sigcount, const uint8_t *cred_id, size_t cred_id_len,
    const uint8_t *cose, size_t cose_len)
{
	uint8_t rph[SHA256_DIGEST_LENGTH];
	size_t o = 0;

	assert(SHA256((const uint8_t *)rp_id, strlen(rp_id), rph) == rph);

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
	size_t alloc_len = 0;

	memset(pairs, 0, sizeof(pairs));

	map = cbor_new_definite_map(5);
	assert(map != NULL);
	pairs[0].key = cbor_build_uint8(1);
	pairs[0].value = cbor_build_uint8(2);		/* kty: EC2 */
	pairs[1].key = cbor_build_uint8(3);
	pairs[1].value = cbor_build_negint8(6);		/* alg: -7 */
	pairs[2].key = cbor_build_negint8(0);
	pairs[2].value = cbor_build_uint8(1);		/* crv: P-256 */
	pairs[3].key = cbor_build_negint8(1);
	pairs[3].value = cbor_build_bytestring(pk->x, sizeof(pk->x));
	pairs[4].key = cbor_build_negint8(2);
	pairs[4].value = cbor_build_bytestring(pk->y, sizeof(pk->y));
	for (size_t i = 0; i < 5; i++) {
		assert(pairs[i].key != NULL && pairs[i].value != NULL);
		assert(cbor_map_add(map, pairs[i]) == true);
		cbor_decref(&pairs[i].key);
		cbor_decref(&pairs[i].value);
	}
	assert((*out_len = cbor_serialize_alloc(map, &out,
	    &alloc_len)) != 0);
	cbor_decref(&map);

	return out;
}

static uint8_t *
cose_key_eddsa(const eddsa_pk_t *pk, size_t *out_len)
{
	struct cbor_pair pairs[4];
	cbor_item_t *map = NULL;
	uint8_t *out = NULL;
	size_t alloc_len = 0;

	memset(pairs, 0, sizeof(pairs));

	map = cbor_new_definite_map(4);
	assert(map != NULL);
	pairs[0].key = cbor_build_uint8(1);
	pairs[0].value = cbor_build_uint8(1);		/* kty: OKP */
	pairs[1].key = cbor_build_uint8(3);
	pairs[1].value = cbor_build_negint8(7);		/* alg: -8 */
	pairs[2].key = cbor_build_negint8(0);
	pairs[2].value = cbor_build_uint8(6);		/* crv: Ed25519 */
	pairs[3].key = cbor_build_negint8(1);
	pairs[3].value = cbor_build_bytestring(pk->x, sizeof(pk->x));
	for (size_t i = 0; i < 4; i++) {
		assert(pairs[i].key != NULL && pairs[i].value != NULL);
		assert(cbor_map_add(map, pairs[i]) == true);
		cbor_decref(&pairs[i].key);
		cbor_decref(&pairs[i].value);
	}
	assert((*out_len = cbor_serialize_alloc(map, &out,
	    &alloc_len)) != 0);
	cbor_decref(&map);

	return out;
}

static size_t
der_int_tlv(const BIGNUM *v, int pad, uint8_t *out)
{
	uint8_t body[40];
	size_t n;

	n = (size_t)BN_num_bytes(v);
	assert(n <= 32);
	assert(BN_bn2bin(v, body) >= 0);
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
	assert(n <= 127);

	out[0] = 0x02;
	out[1] = (uint8_t)n;
	memcpy(out + 2, body, n);

	return 2 + n;
}

/*
 * Re-encode an ECDSA DER signature. With pad=0 this is a canonical
 * decode/encode round-trip; with pad=1 the r INTEGER gets a non-minimal
 * leading zero, i.e. a different encoding of the same (r, s) material.
 */
static size_t
reencode_es256_sig(const uint8_t *in, size_t in_len, int pad, uint8_t *out)
{
	const uint8_t *p = in;
	ECDSA_SIG *s = NULL;
	uint8_t rt[40], st[40];
	size_t rn, sn;

	s = d2i_ECDSA_SIG(NULL, &p, (long)in_len);
	assert(s != NULL);
	rn = der_int_tlv(ECDSA_SIG_get0_r(s), pad, rt);
	sn = der_int_tlv(ECDSA_SIG_get0_s(s), 0, st);
	assert(rn + sn <= 127);

	out[0] = 0x30;
	out[1] = (uint8_t)(rn + sn);
	memcpy(out + 2, rt, rn);
	memcpy(out + 2 + rn, st, sn);

	ECDSA_SIG_free(s);

	return 2 + rn + sn;
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

/* CTAP HID framing for the scripted authenticator (CID 0x00220002). */
static size_t
hid_frames(uint8_t *out, const uint8_t *payload, size_t payload_len)
{
	const uint8_t cid[4] = { 0x00, 0x22, 0x00, 0x02 };
	size_t o = 0, p = 0, n, start;
	uint8_t seq = 0;

	start = o;
	memcpy(out + o, cid, sizeof(cid));
	o += sizeof(cid);
	out[o++] = 0x90; /* CTAP_CMD_CBOR */
	out[o++] = (uint8_t)(payload_len >> 8);
	out[o++] = (uint8_t)(payload_len);
	n = payload_len < 57 ? payload_len : 57;
	memcpy(out + o, payload, n);
	o += n;
	p += n;
	memset(out + o, 0, 64 - (o - start));
	o += 64 - (o - start);

	while (p < payload_len) {
		start = o;
		memcpy(out + o, cid, sizeof(cid));
		o += sizeof(cid);
		out[o++] = seq++;
		n = payload_len - p < 59 ? payload_len - p : 59;
		memcpy(out + o, payload + p, n);
		o += n;
		p += n;
		memset(out + o, 0, 64 - (o - start));
		o += 64 - (o - start);
	}

	return o;
}

/* CTAP2 getAssertion response: {2: h'authdata', 3: h'sig'} */
static size_t
build_assert_reply(uint8_t *out, const uint8_t *authdata,
    size_t authdata_len, const uint8_t *sig, size_t sig_len)
{
	size_t o = 0;

	assert(authdata_len < 256 && sig_len < 256);

	out[o++] = 0x00; /* CTAP1_ERR_SUCCESS */
	out[o++] = 0xa2; /* map(2) */
	out[o++] = 0x02; /* authData */
	out[o++] = 0x58;
	out[o++] = (uint8_t)authdata_len;
	memcpy(out + o, authdata, authdata_len);
	o += authdata_len;
	out[o++] = 0x03; /* signature */
	out[o++] = 0x58;
	out[o++] = (uint8_t)sig_len;
	memcpy(out + o, sig, sig_len);
	o += sig_len;

	return o;
}

static fido_assert_t *
alloc_assert(void)
{
	fido_assert_t *a;

	a = fido_assert_new();
	assert(a != NULL);

	return a;
}

static void
free_assert(fido_assert_t *a)
{
	fido_assert_free(&a);
	assert(a == NULL);
}

static fido_cred_t *
alloc_cred(void)
{
	fido_cred_t *c;

	c = fido_cred_new();
	assert(c != NULL);

	return c;
}

static void
free_cred(fido_cred_t *c)
{
	fido_cred_free(&c);
	assert(c == NULL);
}

/*
 * Build a fido_assert_t carrying a re-signed ES256 assertion over
 * authdata(flags) || resign_cdh, plus the signature. Returns the
 * signature through sig/sig_len when non-NULL.
 */
static fido_assert_t *
make_es256_assert(EC_KEY *ec, uint8_t flags, uint8_t *sig,
    size_t *sig_len)
{
	fido_assert_t *a;
	uint8_t authdata[37];
	uint8_t msg[37 + sizeof(resign_cdh)];
	uint8_t dgst[SHA256_DIGEST_LENGTH];
	uint8_t sigbuf[80];
	size_t n;

	n = build_authdata(authdata, resign_rp_id, flags, 1, NULL, 0, NULL, 0);
	assert(n == sizeof(authdata));
	memcpy(msg, authdata, sizeof(authdata));
	memcpy(msg + sizeof(authdata), resign_cdh, sizeof(resign_cdh));
	assert(SHA256(msg, sizeof(msg), dgst) == dgst);
	n = es256_sign(ec, dgst, sigbuf);
	assert(n > 0 && n <= sizeof(sigbuf));

	a = alloc_assert();
	assert(fido_assert_set_clientdata_hash(a, resign_cdh,
	    sizeof(resign_cdh)) == FIDO_OK);
	assert(fido_assert_set_rp(a, resign_rp_id) == FIDO_OK);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);
	assert(fido_assert_set_authdata_raw(a, 0, authdata,
	    sizeof(authdata)) == FIDO_OK);
	assert(fido_assert_set_sig(a, 0, sigbuf, n) == FIDO_OK);

	if (sig != NULL)
		memcpy(sig, sigbuf, n);
	if (sig_len != NULL)
		*sig_len = n;

	return a;
}

static fido_assert_t *
make_eddsa_assert(EVP_PKEY *sk, uint8_t flags)
{
	fido_assert_t *a;
	uint8_t authdata[37];
	uint8_t msg[37 + sizeof(resign_cdh)];
	uint8_t sig[64];
	size_t n;

	n = build_authdata(authdata, resign_rp_id, flags, 1, NULL, 0, NULL, 0);
	assert(n == sizeof(authdata));
	memcpy(msg, authdata, sizeof(authdata));
	memcpy(msg + sizeof(authdata), resign_cdh, sizeof(resign_cdh));
	n = eddsa_sign(sk, msg, sizeof(msg), sig);
	assert(n == sizeof(sig));

	a = alloc_assert();
	assert(fido_assert_set_clientdata_hash(a, resign_cdh,
	    sizeof(resign_cdh)) == FIDO_OK);
	assert(fido_assert_set_rp(a, resign_rp_id) == FIDO_OK);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);
	assert(fido_assert_set_authdata_raw(a, 0, authdata,
	    sizeof(authdata)) == FIDO_OK);
	assert(fido_assert_set_sig(a, 0, sig, n) == FIDO_OK);

	return a;
}

/* a correctly re-signed assertion verifies */
static void
assert_resign_valid(void)
{
	EC_KEY *ec;
	EVP_PKEY *ed;
	es256_pk_t es256_pk;
	eddsa_pk_t eddsa_pk;
	fido_assert_t *a;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    NULL, NULL);
	assert(fido_assert_verify(a, 0, COSE_ES256, &es256_pk) == FIDO_OK);
	free_assert(a);

	ed = eddsa_key_new(resign_eddsa_sk);
	eddsa_pubkey(ed, &eddsa_pk);
	a = make_eddsa_assert(ed, CTAP_AUTHDATA_USER_PRESENT);
	assert(fido_assert_verify(a, 0, COSE_EDDSA, &eddsa_pk) == FIDO_OK);
	free_assert(a);

	EC_KEY_free(ec);
	EVP_PKEY_free(ed);
}

/* re-encoding the same signature material must not change the verdict */
static void
assert_reencode(void)
{
	EC_KEY *ec;
	EVP_PKEY *ed;
	es256_pk_t es256_pk;
	eddsa_pk_t eddsa_pk;
	fido_assert_t *a;
	cbor_item_t *item;
	uint8_t sig[80], sig1[80];
	uint8_t authdata[37];
	uint8_t *cbor = NULL;
	size_t sig_len, sig1_len, cbor_len, alloc_len;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    sig, &sig_len);

	/* canonical DER decode/encode round-trip */
	sig1_len = reencode_es256_sig(sig, sig_len, 0, sig1);
	assert(sig1_len == sig_len);
	assert(memcmp(sig1, sig, sig_len) == 0);
	assert(fido_assert_set_sig(a, 0, sig1, sig1_len) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256, &es256_pk) == FIDO_OK);

	/*
	 * non-minimal DER encoding of the same (r, s): if the decoder
	 * accepts the padding, the verdict must be unchanged; if the
	 * decoder is strict, the encoding must not be waved through.
	 * either way, re-encoding must not produce an erroneous pass.
	 */
	sig1_len = reencode_es256_sig(sig, sig_len, 1, sig1);
	assert(sig1_len != sig_len || memcmp(sig1, sig, sig_len) != 0);
	assert(fido_assert_set_sig(a, 0, sig1, sig1_len) == FIDO_OK);
	if (same_es256_material(sig, sig_len, sig1, sig1_len))
		assert(fido_assert_verify(a, 0, COSE_ES256,
		    &es256_pk) == FIDO_OK);
	else
		assert(fido_assert_verify(a, 0, COSE_ES256,
		    &es256_pk) != FIDO_OK);
	assert(fido_assert_set_sig(a, 0, sig, sig_len) == FIDO_OK);

	/* CBOR re-serialisation of the authdata container */
	assert(fido_assert_authdata_raw_len(a, 0) == sizeof(authdata));
	memcpy(authdata, fido_assert_authdata_raw_ptr(a, 0),
	    sizeof(authdata));
	item = cbor_build_bytestring(authdata, sizeof(authdata));
	assert(item != NULL);
	assert((cbor_len = cbor_serialize_alloc(item, &cbor,
	    &alloc_len)) != 0);
	assert(fido_assert_set_authdata(a, 0, cbor, cbor_len) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256, &es256_pk) == FIDO_OK);
	cbor_decref(&item);
	free(cbor);
	free_assert(a);

	/* EdDSA: container re-serialisation with a raw 64-byte signature */
	ed = eddsa_key_new(resign_eddsa_sk);
	eddsa_pubkey(ed, &eddsa_pk);
	a = make_eddsa_assert(ed, CTAP_AUTHDATA_USER_PRESENT);
	assert(fido_assert_authdata_raw_len(a, 0) == sizeof(authdata));
	memcpy(authdata, fido_assert_authdata_raw_ptr(a, 0),
	    sizeof(authdata));
	item = cbor_build_bytestring(authdata, sizeof(authdata));
	assert(item != NULL);
	assert((cbor_len = cbor_serialize_alloc(item, &cbor,
	    &alloc_len)) != 0);
	assert(fido_assert_set_authdata(a, 0, cbor, cbor_len) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_EDDSA, &eddsa_pk) == FIDO_OK);
	cbor_decref(&item);
	free(cbor);
	free_assert(a);

	EC_KEY_free(ec);
	EVP_PKEY_free(ed);
}

/* public key substitution must never succeed */
static void
assert_subst_pk(void)
{
	EC_KEY *ec, *alt;
	EVP_PKEY *ed, *ed_alt;
	es256_pk_t es256_pk, es256_alt;
	eddsa_pk_t eddsa_pk, eddsa_alt;
	es384_pk_t es384;
	rs256_pk_t *rs256;
	fido_assert_t *a;

	ec = es256_key_new(resign_es256_sk);
	alt = es256_key_new(resign_es256_alt_sk);
	es256_pubkey(ec, &es256_pk);
	es256_pubkey(alt, &es256_alt);

	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    NULL, NULL);

	/* a different ES256 key must not verify the assertion */
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_alt) == FIDO_ERR_INVALID_SIG);

	/*
	 * algorithm confusion must not verify the assertion: valid
	 * ES384/RS256 keys must not accept an ES256 signature.
	 */
	es384_pubkey_derive(resign_es256_alt_sk, &es384);
	rs256 = rs256_pk_new();
	assert(rs256 != NULL);
	assert(rs256_pk_from_ptr(rs256, resign_rs256_pk,
	    sizeof(resign_rs256_pk)) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES384, &es384) != FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_RS256, rs256) != FIDO_OK);
	free_assert(a);

	ed = eddsa_key_new(resign_eddsa_sk);
	ed_alt = eddsa_key_new(resign_eddsa_alt_sk);
	eddsa_pubkey(ed, &eddsa_pk);
	eddsa_pubkey(ed_alt, &eddsa_alt);
	a = make_eddsa_assert(ed, CTAP_AUTHDATA_USER_PRESENT);
	assert(fido_assert_verify(a, 0, COSE_EDDSA,
	    &eddsa_alt) == FIDO_ERR_INVALID_SIG);
	free_assert(a);

	rs256_pk_free(&rs256);
	EC_KEY_free(ec);
	EC_KEY_free(alt);
	EVP_PKEY_free(ed);
	EVP_PKEY_free(ed_alt);
}

/* signature substitution must never succeed */
static void
assert_subst_sig(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_assert_t *a;
	uint8_t sig[80];
	size_t sig_len;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    sig, &sig_len);

	sig[0] ^= 1;
	assert(fido_assert_set_sig(a, 0, sig, sig_len) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_SIG);
	free_assert(a);
	EC_KEY_free(ec);
}

/* client data hash substitution must never succeed */
static void
assert_subst_cdh(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_assert_t *a;
	uint8_t cdh[sizeof(resign_cdh)];

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    NULL, NULL);

	memcpy(cdh, resign_cdh, sizeof(cdh));
	cdh[0] ^= 1;
	assert(fido_assert_set_clientdata_hash(a, cdh,
	    sizeof(cdh)) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_SIG);
	free_assert(a);
	EC_KEY_free(ec);
}

/* requiring unattested UP/UV flags must never succeed */
static void
assert_flags(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_assert_t *a;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);

	/* authdata carries neither UP nor UV */
	a = make_es256_assert(ec, 0, NULL, NULL);
	assert(fido_assert_set_up(a, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_PARAM);
	assert(fido_assert_set_up(a, FIDO_OPT_FALSE) == FIDO_OK);
	assert(fido_assert_set_uv(a, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_PARAM);
	free_assert(a);

	/* authdata carries UP and UV; requiring them is fine */
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT |
	    CTAP_AUTHDATA_USER_VERIFIED, NULL, NULL);
	assert(fido_assert_set_up(a, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_assert_set_uv(a, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256, &es256_pk) == FIDO_OK);
	free_assert(a);

	EC_KEY_free(ec);
}

/* requiring unattested extensions must never succeed */
static void
assert_ext_mismatch(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_assert_t *a;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    NULL, NULL);
	assert(fido_assert_set_extensions(a,
	    FIDO_EXT_HMAC_SECRET) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_PARAM);
	free_assert(a);
	EC_KEY_free(ec);
}

/* an rp id mismatch must never succeed */
static void
assert_rp_mismatch(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_assert_t *a;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	a = make_es256_assert(ec, CTAP_AUTHDATA_USER_PRESENT,
	    NULL, NULL);
	assert(fido_assert_set_rp(a, "example.com") == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_PARAM);
	free_assert(a);
	EC_KEY_free(ec);
}

/*
 * Build a self-attested credential around the given COSE key and sign it.
 * fmt is "packed" or "fido-u2f" (ES256 only).
 */
static fido_cred_t *
make_selfattest_cred(EC_KEY *ec, EVP_PKEY *ed, int cose_alg,
    const char *fmt, const uint8_t *cose, size_t cose_len,
    const uint8_t *cred_id, size_t cred_id_len, uint8_t uv_flag)
{
	fido_cred_t *c;
	uint8_t authdata[512];
	uint8_t msg[1024];
	uint8_t dgst[SHA256_DIGEST_LENGTH];
	uint8_t sig[80];
	size_t authdata_len, msg_len, sig_len = 0;
	uint8_t flags;

	flags = CTAP_AUTHDATA_USER_PRESENT | CTAP_AUTHDATA_ATT_CRED;
	if (uv_flag)
		flags |= CTAP_AUTHDATA_USER_VERIFIED;

	authdata_len = build_authdata(authdata, resign_rp_id, flags, 1,
	    cred_id, cred_id_len, cose, cose_len);
	assert(authdata_len != 0);

	if (strcmp(fmt, "fido-u2f") == 0) {
		uint8_t rph[SHA256_DIGEST_LENGTH];
		es256_pk_t pk;
		size_t o = 0;

		assert(cose_alg == COSE_ES256);
		es256_pubkey(ec, &pk);
		assert(SHA256((const uint8_t *)resign_rp_id,
		    strlen(resign_rp_id), rph) == rph);
		msg[o++] = 0;
		memcpy(msg + o, rph, sizeof(rph));
		o += sizeof(rph);
		memcpy(msg + o, resign_cdh, sizeof(resign_cdh));
		o += sizeof(resign_cdh);
		memcpy(msg + o, cred_id, cred_id_len);
		o += cred_id_len;
		msg[o++] = 4; /* uncompressed point */
		memcpy(msg + o, pk.x, sizeof(pk.x));
		o += sizeof(pk.x);
		memcpy(msg + o, pk.y, sizeof(pk.y));
		o += sizeof(pk.y);
		msg_len = o;
	} else {
		memcpy(msg, authdata, authdata_len);
		memcpy(msg + authdata_len, resign_cdh, sizeof(resign_cdh));
		msg_len = authdata_len + sizeof(resign_cdh);
	}

	if (cose_alg == COSE_ES256) {
		assert(SHA256(msg, msg_len, dgst) == dgst);
		sig_len = es256_sign(ec, dgst, sig);
	} else {
		sig_len = eddsa_sign(ed, msg, msg_len, sig);
	}
	assert(sig_len != 0);

	c = alloc_cred();
	assert(fido_cred_set_type(c, cose_alg) == FIDO_OK);
	assert(fido_cred_set_clientdata_hash(c, resign_cdh,
	    sizeof(resign_cdh)) == FIDO_OK);
	assert(fido_cred_set_rp(c, resign_rp_id, NULL) == FIDO_OK);
	assert(fido_cred_set_authdata_raw(c, authdata,
	    authdata_len) == FIDO_OK);
	assert(fido_cred_set_fmt(c, fmt) == FIDO_OK);
	assert(fido_cred_set_uv(c, uv_flag ? FIDO_OPT_TRUE :
	    FIDO_OPT_FALSE) == FIDO_OK);
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);

	return c;
}

/* a correctly re-signed self-attestation verifies */
static void
selfattest_valid(void)
{
	EC_KEY *ec;
	EVP_PKEY *ed;
	es256_pk_t es256_pk;
	eddsa_pk_t eddsa_pk;
	fido_cred_t *c;
	uint8_t *cose;
	size_t cose_len;

	/* packed, ES256 */
	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	cose = cose_key_es256(&es256_pk, &cose_len);
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);
	free_cred(c);
	free(cose);

	/* packed, EdDSA */
	ed = eddsa_key_new(resign_eddsa_sk);
	eddsa_pubkey(ed, &eddsa_pk);
	cose = cose_key_eddsa(&eddsa_pk, &cose_len);
	c = make_selfattest_cred(NULL, ed, COSE_EDDSA, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);
	free_cred(c);
	free(cose);

	/* fido-u2f, ES256 */
	cose = cose_key_es256(&es256_pk, &cose_len);
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "fido-u2f", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);
	free_cred(c);
	free(cose);

	EC_KEY_free(ec);
	EVP_PKEY_free(ed);
}

/* credential ID substitution must never succeed */
static void
selfattest_subst_cred_id(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_cred_t *c;
	uint8_t *cose;
	size_t cose_len;
	uint8_t bad_id[sizeof(resign_cred_id)];

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	cose = cose_key_es256(&es256_pk, &cose_len);

	/*
	 * fido-u2f: the credential ID is part of the signed hash, so
	 * swapping attcred.id invalidates the signature.
	 */
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "fido-u2f", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);
	memcpy(bad_id, resign_cred_id, sizeof(bad_id));
	bad_id[0] ^= 1;
	assert(fido_cred_set_id(c, bad_id, sizeof(bad_id)) == FIDO_OK);
	assert(fido_cred_verify_self(c) != FIDO_OK);
	free_cred(c);

	/*
	 * packed: the credential ID is covered through the signed
	 * authdata; re-parsed authdata carrying a substituted ID must
	 * not verify with the original signature.
	 */
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);
	{
		uint8_t authdata[512];
		size_t authdata_len;

		authdata_len = build_authdata(authdata, resign_rp_id,
		    CTAP_AUTHDATA_USER_PRESENT | CTAP_AUTHDATA_ATT_CRED, 1,
		    bad_id, sizeof(bad_id), cose, cose_len);
		assert(fido_cred_set_authdata_raw(c, authdata,
		    authdata_len) == FIDO_OK);
		assert(fido_cred_verify_self(c) != FIDO_OK);
	}
	free_cred(c);

	free(cose);
	EC_KEY_free(ec);
}

/* public key substitution must never succeed */
static void
selfattest_subst_pk(void)
{
	EC_KEY *ec, *alt;
	es256_pk_t es256_pk, es256_alt;
	fido_cred_t *c;
	uint8_t *cose, *cose_alt;
	size_t cose_len, cose_alt_len;
	uint8_t authdata[512];
	size_t authdata_len;

	ec = es256_key_new(resign_es256_sk);
	alt = es256_key_new(resign_es256_alt_sk);
	es256_pubkey(ec, &es256_pk);
	es256_pubkey(alt, &es256_alt);
	cose = cose_key_es256(&es256_pk, &cose_len);
	cose_alt = cose_key_es256(&es256_alt, &cose_alt_len);

	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	/* replace the attested credential public key, keep the signature */
	authdata_len = build_authdata(authdata, resign_rp_id,
	    CTAP_AUTHDATA_USER_PRESENT | CTAP_AUTHDATA_ATT_CRED, 1,
	    resign_cred_id, sizeof(resign_cred_id), cose_alt, cose_alt_len);
	assert(fido_cred_set_authdata_raw(c, authdata,
	    authdata_len) == FIDO_OK);
	assert(fido_cred_verify_self(c) != FIDO_OK);
	free_cred(c);

	free(cose);
	free(cose_alt);
	EC_KEY_free(ec);
	EC_KEY_free(alt);
}

/* client data hash substitution must never succeed */
static void
selfattest_subst_cdh(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_cred_t *c;
	uint8_t *cose;
	size_t cose_len;
	uint8_t cdh[sizeof(resign_cdh)];

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	cose = cose_key_es256(&es256_pk, &cose_len);
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	memcpy(cdh, resign_cdh, sizeof(cdh));
	cdh[0] ^= 1;
	assert(fido_cred_set_clientdata_hash(c, cdh,
	    sizeof(cdh)) == FIDO_OK);
	assert(fido_cred_verify_self(c) != FIDO_OK);
	free_cred(c);

	free(cose);
	EC_KEY_free(ec);
}

/* requiring unattested UV must never succeed */
static void
selfattest_uv(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_cred_t *c;
	uint8_t *cose;
	size_t cose_len;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	cose = cose_key_es256(&es256_pk, &cose_len);

	/* authdata carries UP but not UV */
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_set_uv(c, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_PARAM);
	free_cred(c);

	/* authdata carries UP and UV */
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 1);
	assert(fido_cred_set_uv(c, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_OK);
	free_cred(c);

	free(cose);
	EC_KEY_free(ec);
}

/* self-attestation must not carry an x5c chain */
static void
selfattest_x5c(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_cred_t *c;
	uint8_t *cose;
	size_t cose_len;
	const uint8_t junk_cert[4] = { 0x30, 0x03, 0x02, 0x01 };

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	cose = cose_key_es256(&es256_pk, &cose_len);
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	assert(fido_cred_set_x509(c, junk_cert, sizeof(junk_cert)) ==
	    FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_ARGUMENT);
	free_cred(c);

	free(cose);
	EC_KEY_free(ec);
}

/* re-encoded self-attestation signature must give the same verdict */
static void
selfattest_reencode(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	fido_cred_t *c;
	uint8_t *cose;
	size_t cose_len;
	uint8_t sig[80], sig1[80];
	size_t sig_len, sig1_len;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);
	cose = cose_key_es256(&es256_pk, &cose_len);
	c = make_selfattest_cred(ec, NULL, COSE_ES256, "packed", cose,
	    cose_len, resign_cred_id, sizeof(resign_cred_id), 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	assert(fido_cred_sig_len(c) <= sizeof(sig));
	sig_len = fido_cred_sig_len(c);
	memcpy(sig, fido_cred_sig_ptr(c), sig_len);

	/* canonical DER round-trip */
	sig1_len = reencode_es256_sig(sig, sig_len, 0, sig1);
	assert(fido_cred_set_sig(c, sig1, sig1_len) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	/* non-minimal DER encoding of the same (r, s) */
	sig1_len = reencode_es256_sig(sig, sig_len, 1, sig1);
	assert(fido_cred_set_sig(c, sig1, sig1_len) == FIDO_OK);
	if (same_es256_material(sig, sig_len, sig1, sig1_len))
		assert(fido_cred_verify_self(c) == FIDO_OK);
	else
		assert(fido_cred_verify_self(c) != FIDO_OK);
	free_cred(c);

	free(cose);
	EC_KEY_free(ec);
}

/*
 * Custom-I/O round-trip: a scripted HID authenticator answers a
 * getAssertion request with a response re-signed at runtime.
 */
static void
device_roundtrip(void)
{
	EC_KEY *ec;
	es256_pk_t es256_pk;
	const uint8_t cbor_info[] = { WIREDATA_CTAP_CBOR_INFO };
	fido_dev_t *dev;
	fido_assert_t *a;
	uint8_t *wiredata;
	uint8_t stream[sizeof(cbor_info) + 512];
	uint8_t authdata[37];
	uint8_t msg[37 + sizeof(resign_cdh)];
	uint8_t dgst[SHA256_DIGEST_LENGTH];
	uint8_t sig[80];
	uint8_t reply[256];
	uint8_t frames[512];
	size_t sig_len, reply_len, frames_len, authdata_len;

	ec = es256_key_new(resign_es256_sk);
	es256_pubkey(ec, &es256_pk);

	/* valid re-signed assertion from the scripted authenticator */
	authdata_len = build_authdata(authdata, resign_rp_id,
	    CTAP_AUTHDATA_USER_PRESENT, 1, NULL, 0, NULL, 0);
	memcpy(msg, authdata, authdata_len);
	memcpy(msg + authdata_len, resign_cdh, sizeof(resign_cdh));
	assert(SHA256(msg, authdata_len + sizeof(resign_cdh),
	    dgst) == dgst);
	sig_len = es256_sign(ec, dgst, sig);
	reply_len = build_assert_reply(reply, authdata, authdata_len, sig,
	    sig_len);
	frames_len = hid_frames(frames, reply, reply_len);

	memcpy(stream, cbor_info, sizeof(cbor_info));
	memcpy(stream + sizeof(cbor_info), frames, frames_len);
	wiredata = wiredata_setup(stream, sizeof(cbor_info) + frames_len);
	dev = fido_dev_new();
	assert(dev != NULL);
	setup_dummy_io(dev);
	assert(fido_dev_open(dev, "dummy") == FIDO_OK);
	a = alloc_assert();
	assert(fido_assert_set_clientdata_hash(a, resign_cdh,
	    sizeof(resign_cdh)) == FIDO_OK);
	assert(fido_assert_set_rp(a, resign_rp_id) == FIDO_OK);
	assert(fido_dev_get_assert(dev, a, NULL) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256, &es256_pk) == FIDO_OK);
	assert(fido_assert_flags(a, 0) == CTAP_AUTHDATA_USER_PRESENT);
	free_assert(a);
	assert(fido_dev_close(dev) == FIDO_OK);
	fido_dev_free(&dev);
	wiredata_clear(&wiredata);

	/* same response, one signature byte flipped in transit */
	reply_len = build_assert_reply(reply, authdata, authdata_len, sig,
	    sig_len);
	reply[reply_len - 1] ^= 1;
	frames_len = hid_frames(frames, reply, reply_len);

	memcpy(stream, cbor_info, sizeof(cbor_info));
	memcpy(stream + sizeof(cbor_info), frames, frames_len);
	wiredata = wiredata_setup(stream, sizeof(cbor_info) + frames_len);
	dev = fido_dev_new();
	assert(dev != NULL);
	setup_dummy_io(dev);
	assert(fido_dev_open(dev, "dummy") == FIDO_OK);
	a = alloc_assert();
	assert(fido_assert_set_clientdata_hash(a, resign_cdh,
	    sizeof(resign_cdh)) == FIDO_OK);
	assert(fido_assert_set_rp(a, resign_rp_id) == FIDO_OK);
	assert(fido_dev_get_assert(dev, a, NULL) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_SIG);
	free_assert(a);
	assert(fido_dev_close(dev) == FIDO_OK);
	fido_dev_free(&dev);
	wiredata_clear(&wiredata);

	/* authenticator drops the UP flag while the client requires it */
	authdata_len = build_authdata(authdata, resign_rp_id, 0, 1, NULL, 0,
	    NULL, 0);
	memcpy(msg, authdata, authdata_len);
	memcpy(msg + authdata_len, resign_cdh, sizeof(resign_cdh));
	assert(SHA256(msg, authdata_len + sizeof(resign_cdh),
	    dgst) == dgst);
	sig_len = es256_sign(ec, dgst, sig);
	reply_len = build_assert_reply(reply, authdata, authdata_len, sig,
	    sig_len);
	frames_len = hid_frames(frames, reply, reply_len);

	memcpy(stream, cbor_info, sizeof(cbor_info));
	memcpy(stream + sizeof(cbor_info), frames, frames_len);
	wiredata = wiredata_setup(stream, sizeof(cbor_info) + frames_len);
	dev = fido_dev_new();
	assert(dev != NULL);
	setup_dummy_io(dev);
	assert(fido_dev_open(dev, "dummy") == FIDO_OK);
	a = alloc_assert();
	assert(fido_assert_set_clientdata_hash(a, resign_cdh,
	    sizeof(resign_cdh)) == FIDO_OK);
	assert(fido_assert_set_rp(a, resign_rp_id) == FIDO_OK);
	assert(fido_assert_set_up(a, FIDO_OPT_TRUE) == FIDO_OK);
	assert(fido_dev_get_assert(dev, a, NULL) == FIDO_OK);
	assert(fido_assert_verify(a, 0, COSE_ES256,
	    &es256_pk) == FIDO_ERR_INVALID_PARAM);
	free_assert(a);
	assert(fido_dev_close(dev) == FIDO_OK);
	fido_dev_free(&dev);
	wiredata_clear(&wiredata);

	EC_KEY_free(ec);
}

int
main(void)
{
	fido_init(0);

	assert_resign_valid();
	assert_reencode();
	assert_subst_pk();
	assert_subst_sig();
	assert_subst_cdh();
	assert_flags();
	assert_ext_mismatch();
	assert_rp_mismatch();
	selfattest_valid();
	selfattest_subst_cred_id();
	selfattest_subst_pk();
	selfattest_subst_cdh();
	selfattest_uv();
	selfattest_x5c();
	selfattest_reencode();
	device_roundtrip();

	exit(0);
}
