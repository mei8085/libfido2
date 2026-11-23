/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Regression tests for the algorithm binding of the fido-u2f attestation
 * format.
 *
 * A fido-u2f attestation statement covers
 *
 *	0x00 || rpIdHash || clientDataHash || credentialId ||
 *	0x04 || x || y
 *
 * i.e. exactly one P-256 public key.  Historically fido_cred_verify() and
 * fido_cred_verify_self() computed this blob from the ES256 view of the
 * attested credential's public key union regardless of the credential's
 * actual COSE algorithm.  For a key larger than 64 bytes (RS256/ES384),
 * only a prefix of the key was signed, leaving the remainder free to be
 * replaced after the signature had been obtained.
 *
 * The checks below pin down the boundaries of the fix:
 *
 * - a genuine ES256 fido-u2f self-attestation and basic attestation keep
 *   verifying with FIDO_OK (compatibility);
 * - a fido-u2f credential of any other COSE algorithm is rejected with
 *   FIDO_ERR_INVALID_ARGUMENT, a verdict distinguishable from a plain
 *   signature mismatch (FIDO_ERR_INVALID_SIG);
 * - a fido-u2f attestation statement that names a non-ES256 algorithm is
 *   rejected the same way, while an omitted algorithm keeps the
 *   historical ES256 default;
 * - substituting the attested public key of an ES256 credential still
 *   fails with FIDO_ERR_INVALID_SIG;
 * - a rejected credential leaves no partial state behind, and independent
 *   credential objects do not influence one another.
 */

#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#define _FIDO_INTERNAL

#include <fido.h>
#include <fido/es256.h>

static const char rp_id[] = "localhost";
static const uint8_t cdh[SHA256_DIGEST_LENGTH] = {
	0xec, 0x8d, 0x8f, 0x78, 0x42, 0x4a, 0x2b, 0xb7,
	0x82, 0x34, 0xaa, 0xca, 0x07, 0xa1, 0xf6, 0x56,
	0x42, 0x1c, 0xb6, 0xf6, 0xb3, 0x00, 0x86, 0x52,
	0x35, 0x2d, 0xa2, 0x62, 0x4a, 0xbe, 0x89, 0x76,
};
static const uint8_t cred_id[16] = {
	0x4f, 0x72, 0x98, 0x42, 0x4a, 0xe1, 0x17, 0xa5,
	0x85, 0xa0, 0xef, 0x3b, 0x11, 0x24, 0x4a, 0x3d,
};

/* ---- CBOR helpers ---------------------------------------------------- */

/*
 * Wrap `len` bytes into a definite-length CBOR bytestring.  The returned
 * buffer is heap allocated and owned by the caller.
 */
static unsigned char *
cbor_wrap(const uint8_t *in, size_t len, size_t *out_len)
{
	unsigned char	*out;
	size_t		 hdr_len;

	if (len < 24)
		hdr_len = 1;
	else if (len <= UINT8_MAX)
		hdr_len = 2;
	else
		hdr_len = 3;

	assert((out = malloc(hdr_len + len)) != NULL);

	if (len < 24) {
		out[0] = (unsigned char)(0x40 | len);
	} else if (len <= UINT8_MAX) {
		out[0] = 0x58;
		out[1] = (unsigned char)len;
	} else {
		out[0] = 0x59;
		out[1] = (unsigned char)(len >> 8);
		out[2] = (unsigned char)(len & 0xff);
	}

	memcpy(out + hdr_len, in, len);
	*out_len = hdr_len + len;

	return (out);
}

static size_t
push_bytes(unsigned char *out, size_t o, const uint8_t *p, size_t len)
{
	memcpy(out + o, p, len);

	return (o + len);
}

/* ---- key material ---------------------------------------------------- */

static EC_KEY *
ec_key_new(void)
{
	EC_KEY *ec;

	assert((ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) != NULL);
	assert(EC_KEY_generate_key(ec) == 1);

	return (ec);
}

static void
ec_pubkey(const EC_KEY *ec, es256_pk_t *pk)
{
	assert(es256_pk_from_EC_KEY(pk, ec) == FIDO_OK);
}

/*
 * Sign `dgst` with `ec` and return a DER-encoded ECDSA signature.  The
 * returned buffer is heap allocated and owned by the caller.
 */
static unsigned char *
ec_sign(EC_KEY *ec, const uint8_t *dgst, size_t dgst_len, size_t *out_len)
{
	ECDSA_SIG	*sig = NULL;
	unsigned char	*der = NULL;
	unsigned char	*p;
	int		 len;

	assert((sig = ECDSA_do_sign(dgst, (int)dgst_len, ec)) != NULL);
	assert((len = i2d_ECDSA_SIG(sig, NULL)) > 0);
	assert((der = malloc((size_t)len)) != NULL);
	p = der;
	assert(i2d_ECDSA_SIG(sig, &p) == len);
	ECDSA_SIG_free(sig);
	*out_len = (size_t)len;

	return (der);
}

/* ---- authData / attestation statement builders ----------------------- */

/*
 * rpIdHash || flags || signCount [ || aaguid || idLen || id || coseKey ]
 */
static size_t
build_authdata(uint8_t *out, uint8_t flags, const uint8_t *id, size_t id_len,
    const uint8_t *cose, size_t cose_len)
{
	uint8_t rph[SHA256_DIGEST_LENGTH];
	size_t	o = 0;

	assert(SHA256((const uint8_t *)rp_id, strlen(rp_id), rph) == rph);

	o = push_bytes(out, o, rph, sizeof(rph));
	out[o++] = flags;
	memset(out + o, 0, 4); /* signCount */
	o += 4;
	memset(out + o, 0, 16); /* aaguid */
	o += 16;
	out[o++] = (uint8_t)(id_len >> 8);
	out[o++] = (uint8_t)(id_len & 0xff);
	o = push_bytes(out, o, id, id_len);
	o = push_bytes(out, o, cose, cose_len);

	return (o);
}

/* COSE_Key { 1: 2, 3: -7, -1: 1, -2: x, -3: y } */
static size_t
cose_es256(const es256_pk_t *pk, uint8_t *out)
{
	size_t o = 0;

	out[o++] = 0xa5;		/* map(5) */
	out[o++] = 0x01;		/* kty */
	out[o++] = 0x02;		/* EC2 */
	out[o++] = 0x03;		/* alg */
	out[o++] = 0x26;		/* ES256 (-7) */
	out[o++] = 0x20;		/* crv (-1) */
	out[o++] = 0x01;		/* P-256 */
	out[o++] = 0x21;		/* x (-2) */
	out[o++] = 0x58;
	out[o++] = 0x20;
	o = push_bytes(out, o, pk->x, sizeof(pk->x));
	out[o++] = 0x22;		/* y (-3) */
	out[o++] = 0x58;
	out[o++] = 0x20;
	o = push_bytes(out, o, pk->y, sizeof(pk->y));

	return (o);
}

/* COSE_Key { 1: 1, 3: -8, -1: 6, -2: x } -- always 32 bytes of key */
static size_t
cose_eddsa(uint8_t *out)
{
	size_t o = 0;

	out[o++] = 0xa4;		/* map(4) */
	out[o++] = 0x01;		/* kty */
	out[o++] = 0x01;		/* OKP */
	out[o++] = 0x03;		/* alg */
	out[o++] = 0x27;		/* EdDSA (-8) */
	out[o++] = 0x20;		/* crv (-1) */
	out[o++] = 0x06;		/* Ed25519 */
	out[o++] = 0x21;		/* x (-2) */
	out[o++] = 0x58;
	out[o++] = 0x20;
	memset(out + o, 0x5a, 32);
	o += 32;

	return (o);
}

/* COSE_Key { 1: 2, 3: -35, -1: 2, -2: x, -3: y } -- 96 bytes of key */
static size_t
cose_es384(uint8_t *out)
{
	size_t o = 0;

	out[o++] = 0xa5;		/* map(5) */
	out[o++] = 0x01;		/* kty */
	out[o++] = 0x02;		/* EC2 */
	out[o++] = 0x03;		/* alg */
	out[o++] = 0x38;		/* negative two-byte argument */
	out[o++] = 0x22;		/* ES384 (-35) */
	out[o++] = 0x20;		/* crv (-1) */
	out[o++] = 0x02;		/* P-384 */
	out[o++] = 0x21;		/* x (-2) */
	out[o++] = 0x58;
	out[o++] = 0x30;
	memset(out + o, 0x33, 48);
	o += 48;
	out[o++] = 0x22;		/* y (-3) */
	out[o++] = 0x58;
	out[o++] = 0x30;
	memset(out + o, 0x44, 48);
	o += 48;

	return (o);
}

/* COSE_Key { 1: 3, 3: -257, -1: n(256), -2: e } */
static size_t
cose_rs256(uint8_t *out)
{
	size_t o = 0;

	out[o++] = 0xa4;		/* map(4) */
	out[o++] = 0x01;		/* kty */
	out[o++] = 0x03;		/* RSA */
	out[o++] = 0x03;		/* alg */
	out[o++] = 0x39;		/* negative two-byte argument */
	out[o++] = 0x01;
	out[o++] = 0x00;		/* RS256 (-257) */
	out[o++] = 0x20;		/* n (-1) */
	out[o++] = 0x59;
	out[o++] = 0x01;
	out[o++] = 0x00;
	memset(out + o, 0xa5, 256);
	o += 256;
	out[o++] = 0x21;		/* e (-2) */
	out[o++] = 0x43;		/* 3-byte bytestring */
	out[o++] = 0x01;
	out[o++] = 0x00;
	out[o++] = 0x01;

	return (o);
}

/* ---- credential helpers ---------------------------------------------- */

static fido_cred_t *
alloc_cred(void)
{
	fido_cred_t *c;

	assert((c = fido_cred_new()) != NULL);

	return (c);
}

static void
free_cred(fido_cred_t *c)
{
	fido_cred_free(&c);
	assert(c == NULL);
}

/*
 * Build a credential whose authData carries `cose`/`cose_len` as its
 * attested credential.  The credential ID is fixed, and the signature is
 * left to the caller.
 */
static fido_cred_t *
make_cred(int cose_alg, const uint8_t *cose, size_t cose_len, const char *fmt)
{
	fido_cred_t	*c;
	uint8_t		 authdata[512];
	unsigned char	*wrapped;
	size_t		 authdata_len, wrapped_len;

	authdata_len = build_authdata(authdata,
	    CTAP_AUTHDATA_USER_PRESENT | CTAP_AUTHDATA_ATT_CRED, cred_id,
	    sizeof(cred_id), cose, cose_len);
	wrapped = cbor_wrap(authdata, authdata_len, &wrapped_len);

	c = alloc_cred();
	assert(fido_cred_set_type(c, cose_alg) == FIDO_OK);
	assert(fido_cred_set_clientdata_hash(c, cdh, sizeof(cdh)) == FIDO_OK);
	assert(fido_cred_set_rp(c, rp_id, NULL) == FIDO_OK);
	assert(fido_cred_set_authdata(c, wrapped, wrapped_len) == FIDO_OK);
	assert(fido_cred_set_fmt(c, fmt) == FIDO_OK);

	free(wrapped);

	return (c);
}

/*
 * The blob covered by a fido-u2f attestation: 0x00 || rpIdHash ||
 * clientDataHash || credentialId || 0x04 || x || y.
 */
static size_t
u2f_blob(const uint8_t *x, const uint8_t *y, uint8_t *out)
{
	uint8_t	rph[SHA256_DIGEST_LENGTH];
	size_t	o = 0;

	assert(SHA256((const uint8_t *)rp_id, strlen(rp_id), rph) == rph);

	out[o++] = 0x00;
	o = push_bytes(out, o, rph, sizeof(rph));
	o = push_bytes(out, o, cdh, sizeof(cdh));
	o = push_bytes(out, o, cred_id, sizeof(cred_id));
	out[o++] = 0x04;
	o = push_bytes(out, o, x, 32);
	o = push_bytes(out, o, y, 32);

	return (o);
}

/* DER encoding of a self-signed certificate carrying `ec` as its key */
static unsigned char *
selfsigned_x509(EC_KEY *ec, size_t *out_len)
{
	X509		*x = NULL;
	EVP_PKEY	*pkey = NULL;
	X509_NAME	*name;
	unsigned char	*der = NULL, *p;
	int		 len;

	assert((pkey = EVP_PKEY_new()) != NULL);
	assert(EVP_PKEY_set1_EC_KEY(pkey, ec) == 1);
	assert((x = X509_new()) != NULL);
	assert(X509_set_version(x, 2) == 1);
	assert(ASN1_INTEGER_set(X509_get_serialNumber(x), 1) == 1);
	assert(X509_gmtime_adj(X509_get_notBefore(x), 0) != NULL);
	assert(X509_gmtime_adj(X509_get_notAfter(x), 3600) != NULL);
	assert((name = X509_get_subject_name(x)) != NULL);
	assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	    (const unsigned char *)"u2f test", -1, -1, 0) == 1);
	assert(X509_set_issuer_name(x, name) == 1);
	assert(X509_set_pubkey(x, pkey) == 1);
	assert(X509_sign(x, pkey, EVP_sha256()) > 0);
	assert((len = i2d_X509(x, NULL)) > 0);
	assert((der = malloc((size_t)len)) != NULL);
	p = der;
	assert(i2d_X509(x, &p) == len);
	*out_len = (size_t)len;

	X509_free(x);
	EVP_PKEY_free(pkey);

	return (der);
}

/*
 * Assemble an attStmt map with an explicit "alg".  Follows the ownership
 * convention of es256_pk_encode(): cbor_map_add() and cbor_array_push()
 * take their own references, so the locally built items are released
 * before returning.
 */
static unsigned char *
attstmt_cbor(int alg, const uint8_t *sig, size_t sig_len, const uint8_t *x5c,
    size_t x5c_len, size_t *out_len)
{
	struct cbor_pair	 kv[3];
	cbor_item_t		*map = NULL, *arr = NULL, *der = NULL;
	unsigned char		*out = NULL;
	size_t			 alloc_len = 0;

	memset(kv, 0, sizeof(kv));

	if ((map = cbor_new_definite_map(3)) == NULL)
		assert(0);
	assert((kv[0].key = cbor_build_string("alg")) != NULL);
	assert((kv[0].value = cbor_build_negint8((uint8_t)(-alg - 1))) != NULL);
	assert((kv[1].key = cbor_build_string("sig")) != NULL);
	assert((kv[1].value = cbor_build_bytestring(sig, sig_len)) != NULL);
	assert((kv[2].key = cbor_build_string("x5c")) != NULL);
	assert((arr = cbor_new_definite_array(1)) != NULL);
	assert((der = cbor_build_bytestring(x5c, x5c_len)) != NULL);
	assert(cbor_array_push(arr, der) == true);
	kv[2].value = arr;

	for (size_t i = 0; i < 3; i++)
		assert(cbor_map_add(map, kv[i]) == true);

	assert((*out_len = cbor_serialize_alloc(map, &out, &alloc_len)) != 0);

	cbor_decref(&map);
	cbor_decref(&der);
	for (size_t i = 0; i < 3; i++) {
		cbor_decref(&kv[i].key);
		cbor_decref(&kv[i].value);
	}

	return (out);
}

/* ---- valid / compatible scenarios ------------------------------------ */

/*
 * A genuine ES256 fido-u2f self-attestation verifies.  The credential key
 * is fully covered by the signed blob.
 */
static void
u2f_es256_self_ok(void)
{
	EC_KEY		*ec;
	es256_pk_t	 pk;
	fido_cred_t	*c;
	uint8_t		 cose[128], blob[256], dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig;
	size_t		 cose_len, blob_len, sig_len;

	ec = ec_key_new();
	ec_pubkey(ec, &pk);
	cose_len = cose_es256(&pk, cose);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(ec, dgst, sizeof(dgst), &sig_len);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_pubkey_len(c) == sizeof(pk));
	assert(memcmp(fido_cred_pubkey_ptr(c), &pk, sizeof(pk)) == 0);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	free_cred(c);
	free(sig);
	EC_KEY_free(ec);
}

/*
 * A genuine ES256 fido-u2f basic attestation (x5c + signature by the
 * attestation key) verifies.
 */
static void
u2f_es256_basic_ok(void)
{
	EC_KEY		*cred_ec, *att_ec;
	es256_pk_t	 pk;
	fido_cred_t	*c;
	uint8_t		 cose[128], blob[256], dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig, *x5c;
	size_t		 cose_len, blob_len, sig_len, x5c_len;

	cred_ec = ec_key_new();
	att_ec = ec_key_new();
	ec_pubkey(cred_ec, &pk);
	cose_len = cose_es256(&pk, cose);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(att_ec, dgst, sizeof(dgst), &sig_len);
	x5c = selfsigned_x509(att_ec, &x5c_len);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_x509(c, x5c, x5c_len) == FIDO_OK);
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify(c) == FIDO_OK);

	free_cred(c);
	free(sig);
	free(x5c);
	EC_KEY_free(cred_ec);
	EC_KEY_free(att_ec);
}

/*
 * An omitted "alg" keeps the historical ES256 default.
 */
static void
u2f_omitted_alg_ok(void)
{
	EC_KEY		*cred_ec, *att_ec;
	es256_pk_t	 pk;
	fido_cred_t	*c;
	uint8_t		 cose[128], blob[256], dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig, *x5c;
	size_t		 cose_len, blob_len, sig_len, x5c_len;

	cred_ec = ec_key_new();
	att_ec = ec_key_new();
	ec_pubkey(cred_ec, &pk);
	cose_len = cose_es256(&pk, cose);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(att_ec, dgst, sizeof(dgst), &sig_len);
	x5c = selfsigned_x509(att_ec, &x5c_len);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	/* no "alg" entry: set_sig()/set_x509() leave it COSE_UNSPEC */
	assert(fido_cred_set_x509(c, x5c, x5c_len) == FIDO_OK);
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify(c) == FIDO_OK);

	free_cred(c);
	free(sig);
	free(x5c);
	EC_KEY_free(cred_ec);
	EC_KEY_free(att_ec);
}

/*
 * The packed format is unaffected by the fido-u2f check.
 */
static void
packed_unaffected(void)
{
	EC_KEY		*ec;
	es256_pk_t	 pk;
	fido_cred_t	*c;
	uint8_t		 cose[128];
	size_t		 cose_len;

	ec = ec_key_new();
	ec_pubkey(ec, &pk);
	cose_len = cose_es256(&pk, cose);

	c = make_cred(COSE_ES256, cose, cose_len, "packed");
	/* packed verification reaches the signature check; a bogus
	 * signature must be reported as such, not as a format error */
	assert(fido_cred_set_sig(c, (const uint8_t *)"\x30\x00", 2) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_SIG);

	free_cred(c);
	EC_KEY_free(ec);
}

/* ---- rejected scenarios ---------------------------------------------- */

/*
 * A fido-u2f credential of any non-ES256 algorithm is rejected before any
 * signature work, with a verdict distinct from a signature mismatch.
 */
static void
u2f_reject_non_es256(int cose_alg, const uint8_t *cose, size_t cose_len)
{
	fido_cred_t	*c;
	uint8_t		 sig[64];

	memset(sig, 0x11, sizeof(sig));

	c = make_cred(cose_alg, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_sig(c, sig, sizeof(sig)) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_ARGUMENT);
	/* the verdict is stable across repeated calls and objects stay
	 * readable */
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_ARGUMENT);
	assert(fido_cred_id_len(c) == sizeof(cred_id));
	assert(memcmp(fido_cred_id_ptr(c), cred_id, sizeof(cred_id)) == 0);
	free_cred(c);
}

/*
 * The historical flaw, via basic attestation: an RS256 credential whose
 * fido-u2f attestation signature only covered the first 64 bytes of its
 * 259-byte public key.  Pre-fix, fido_cred_verify() returned FIDO_OK for
 * such a credential, even though the remainder of the RSA modulus could be
 * replaced after the attestation statement had been issued.  The credential
 * must now be rejected with FIDO_ERR_INVALID_ARGUMENT.
 */
static void
u2f_reject_rs256_prefix(void)
{
	EC_KEY		*att_ec;
	fido_cred_t	*c;
	uint8_t		 cose[300], blob[256], dgst[SHA256_DIGEST_LENGTH];
	uint8_t		 prefix[64];
	unsigned char	*sig, *x5c;
	size_t		 cose_len, blob_len, sig_len, x5c_len;

	att_ec = ec_key_new();
	cose_len = cose_rs256(cose);
	/* the pre-fix code hashed the first 64 bytes of the RSA modulus
	 * (0xa5 in cose_rs256()) as if they were an ES256 point */
	memset(prefix, 0xa5, sizeof(prefix));
	blob_len = u2f_blob(prefix, prefix + 32, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(att_ec, dgst, sizeof(dgst), &sig_len);
	x5c = selfsigned_x509(att_ec, &x5c_len);

	c = make_cred(COSE_RS256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_x509(c, x5c, x5c_len) == FIDO_OK);
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify(c) == FIDO_ERR_INVALID_ARGUMENT);

	free_cred(c);
	free(sig);
	free(x5c);
	EC_KEY_free(att_ec);
}

/*
 * A fido-u2f attestation statement naming a non-ES256 algorithm is
 * rejected, even when the credential itself is ES256.
 */
static void
u2f_reject_attstmt_alg(void)
{
	EC_KEY		*cred_ec, *att_ec;
	es256_pk_t	 pk;
	fido_cred_t	*c;
	uint8_t		 cose[128], blob[256], dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig, *x5c, *stmt;
	size_t		 cose_len, blob_len, sig_len, x5c_len, stmt_len;

	cred_ec = ec_key_new();
	att_ec = ec_key_new();
	ec_pubkey(cred_ec, &pk);
	cose_len = cose_es256(&pk, cose);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(att_ec, dgst, sizeof(dgst), &sig_len);
	x5c = selfsigned_x509(att_ec, &x5c_len);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	stmt = attstmt_cbor(COSE_ES384, sig, sig_len, x5c, x5c_len,
	    &stmt_len);
	assert(fido_cred_set_attstmt(c, stmt, stmt_len) == FIDO_OK);
	assert(fido_cred_verify(c) == FIDO_ERR_INVALID_ARGUMENT);

	free_cred(c);
	free(stmt);

	/* the same statement with the ES256 algorithm verifies */
	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	stmt = attstmt_cbor(COSE_ES256, sig, sig_len, x5c, x5c_len,
	    &stmt_len);
	assert(fido_cred_set_attstmt(c, stmt, stmt_len) == FIDO_OK);
	assert(fido_cred_verify(c) == FIDO_OK);

	free_cred(c);
	free(stmt);
	free(sig);
	free(x5c);
	EC_KEY_free(cred_ec);
	EC_KEY_free(att_ec);
}

/*
 * Substituting the attested public key of an ES256 fido-u2f credential
 * still invalidates the signature (FIDO_ERR_INVALID_SIG).
 */
static void
u2f_es256_pk_substitution(void)
{
	EC_KEY		*ec, *alt;
	es256_pk_t	 pk, alt_pk;
	fido_cred_t	*c;
	uint8_t		 cose[128], cose_alt[128], blob[256];
	uint8_t		 dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig;
	size_t		 cose_len, cose_alt_len, blob_len, sig_len;

	ec = ec_key_new();
	alt = ec_key_new();
	ec_pubkey(ec, &pk);
	ec_pubkey(alt, &alt_pk);
	cose_len = cose_es256(&pk, cose);
	cose_alt_len = cose_es256(&alt_pk, cose_alt);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(ec, dgst, sizeof(dgst), &sig_len);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	/* swap in a different key, keep the original signature */
	{
		uint8_t		 authdata[512];
		unsigned char	*wrapped;
		size_t		 authdata_len, wrapped_len;

		authdata_len = build_authdata(authdata,
		    CTAP_AUTHDATA_USER_PRESENT | CTAP_AUTHDATA_ATT_CRED,
		    cred_id, sizeof(cred_id), cose_alt, cose_alt_len);
		wrapped = cbor_wrap(authdata, authdata_len, &wrapped_len);
		assert(fido_cred_set_authdata(c, wrapped,
		    wrapped_len) == FIDO_OK);
		free(wrapped);
	}
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_SIG);

	free_cred(c);
	free(sig);
	EC_KEY_free(ec);
	EC_KEY_free(alt);
}

/* ---- state isolation -------------------------------------------------- */

/*
 * A rejected fido-u2f credential must not poison the object: setting a
 * valid payload afterwards must verify, and vice versa.
 */
static void
state_recovery(void)
{
	EC_KEY		*ec;
	es256_pk_t	 pk;
	fido_cred_t	*c;
	uint8_t		 cose[128], bad_cose[300], blob[256];
	uint8_t		 dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig;
	size_t		 cose_len, bad_cose_len, blob_len, sig_len;

	ec = ec_key_new();
	ec_pubkey(ec, &pk);
	cose_len = cose_es256(&pk, cose);
	bad_cose_len = cose_rs256(bad_cose);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(ec, dgst, sizeof(dgst), &sig_len);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	/* successfully re-parse a non-ES256 credential, then a valid one */
	free_cred(c);
	c = make_cred(COSE_RS256, bad_cose, bad_cose_len, "fido-u2f");
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_ERR_INVALID_ARGUMENT);
	free_cred(c);

	c = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_sig(c, sig, sig_len) == FIDO_OK);
	assert(fido_cred_verify_self(c) == FIDO_OK);

	free_cred(c);
	free(sig);
	EC_KEY_free(ec);
}

/*
 * Independent credential objects do not observe each other's verdicts.
 */
static void
state_isolation(void)
{
	EC_KEY		*ec;
	es256_pk_t	 pk;
	fido_cred_t	*good, *bad;
	uint8_t		 cose[128], bad_cose[300], blob[256];
	uint8_t		 dgst[SHA256_DIGEST_LENGTH];
	unsigned char	*sig;
	size_t		 cose_len, bad_cose_len, blob_len, sig_len;

	ec = ec_key_new();
	ec_pubkey(ec, &pk);
	cose_len = cose_es256(&pk, cose);
	bad_cose_len = cose_rs256(bad_cose);
	blob_len = u2f_blob(pk.x, pk.y, blob);
	assert(SHA256(blob, blob_len, dgst) == dgst);
	sig = ec_sign(ec, dgst, sizeof(dgst), &sig_len);

	good = make_cred(COSE_ES256, cose, cose_len, "fido-u2f");
	assert(fido_cred_set_sig(good, sig, sig_len) == FIDO_OK);
	bad = make_cred(COSE_RS256, bad_cose, bad_cose_len, "fido-u2f");
	assert(fido_cred_set_sig(bad, sig, sig_len) == FIDO_OK);

	assert(fido_cred_verify_self(bad) == FIDO_ERR_INVALID_ARGUMENT);
	assert(fido_cred_verify_self(good) == FIDO_OK);
	assert(fido_cred_verify_self(bad) == FIDO_ERR_INVALID_ARGUMENT);
	assert(fido_cred_verify_self(good) == FIDO_OK);

	free_cred(good);
	free_cred(bad);
	free(sig);
	EC_KEY_free(ec);
}

int
main(void)
{
	fido_init(0);

	u2f_es256_self_ok();
	u2f_es256_basic_ok();
	u2f_omitted_alg_ok();
	packed_unaffected();

	{
		uint8_t cose[64];
		size_t len = cose_eddsa(cose);
		u2f_reject_non_es256(COSE_EDDSA, cose, len);
	}
	{
		uint8_t cose[128];
		size_t len = cose_es384(cose);
		u2f_reject_non_es256(COSE_ES384, cose, len);
	}
	u2f_reject_rs256_prefix();
	u2f_reject_attstmt_alg();
	u2f_es256_pk_substitution();

	state_recovery();
	state_isolation();

	exit(0);
}
