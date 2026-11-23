/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fido.h>

#define FLAGS_UP	0x01
#define FLAGS_UV	0x04
#define FLAGS_ATTCRED	0x40
#define FLAGS_EXTDATA	0x80
#define FLAGS_RESERVED	0x3a /* every reserved flag bit */
#define AUTHDATA_LEN	37

/*
 * Wrap an authenticator data payload (or any byte string) into its canonical
 * CBOR definite-length bytestring encoding. The returned buffer is heap
 * allocated and owned by the caller.
 */
static unsigned char *
cbor_wrap(const unsigned char *payload, size_t payload_len, size_t *out_len)
{
	unsigned char	*out;
	size_t		 hdr_len;

	if (payload_len < 24)
		hdr_len = 1;
	else if (payload_len <= UINT8_MAX)
		hdr_len = 2;
	else if (payload_len <= UINT16_MAX)
		hdr_len = 3;
	else
		hdr_len = 5; /* enough for everything used below */

	assert((out = malloc(hdr_len + payload_len)) != NULL);

	if (payload_len < 24) {
		out[0] = (unsigned char)(0x40 | payload_len);
	} else if (payload_len <= UINT8_MAX) {
		out[0] = 0x58;
		out[1] = (unsigned char)payload_len;
	} else if (payload_len <= UINT16_MAX) {
		out[0] = 0x59;
		out[1] = (unsigned char)(payload_len >> 8);
		out[2] = (unsigned char)(payload_len & 0xff);
	} else {
		out[0] = 0x5a;
		out[1] = (unsigned char)(payload_len >> 24);
		out[2] = (unsigned char)(payload_len >> 16);
		out[3] = (unsigned char)(payload_len >> 8);
		out[4] = (unsigned char)(payload_len & 0xff);
	}

	memcpy(out + hdr_len, payload, payload_len);
	*out_len = hdr_len + payload_len;

	return (out);
}

/* Build a minimal, spec-conformant assertion authenticator data payload. */
static unsigned char *
assert_payload(uint8_t flags, size_t *out_len)
{
	unsigned char	*p;

	assert((p = calloc(1, AUTHDATA_LEN)) != NULL);
	p[32] = flags; /* rpIdHash (32 zero bytes), flags, sigcount (0) */
	*out_len = AUTHDATA_LEN;

	return (p);
}

/* Append a CBOR-encoded empty extensions map (0xa0) to a payload. */
static unsigned char *
append_extensions(unsigned char *p, size_t *len)
{
	assert((p = realloc(p, *len + 1)) != NULL);
	p[(*len)++] = 0xa0;

	return (p);
}

static void
assert_clean_state(const fido_assert_t *a, size_t idx)
{
	assert(fido_assert_authdata_ptr(a, idx) == NULL);
	assert(fido_assert_authdata_len(a, idx) == 0);
	assert(fido_assert_authdata_raw_ptr(a, idx) == NULL);
	assert(fido_assert_authdata_raw_len(a, idx) == 0);
	assert(fido_assert_flags(a, idx) == 0);
	assert(fido_assert_sigcount(a, idx) == 0);
}

/* A valid payload decodes successfully and round-trips its bytes. */
static void
assert_valid(void)
{
	fido_assert_t	*a;
	unsigned char	*payload;
	unsigned char	*blob;
	size_t		 payload_len, blob_len;

	payload = assert_payload(FLAGS_UP, &payload_len);
	blob = cbor_wrap(payload, payload_len, &blob_len);

	a = fido_assert_new();
	assert(a != NULL);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);
	assert(fido_assert_set_authdata(a, 0, blob, blob_len) == FIDO_OK);
	assert(fido_assert_flags(a, 0) == FLAGS_UP);
	assert(fido_assert_sigcount(a, 0) == 0);
	assert(fido_assert_authdata_len(a, 0) == blob_len);
	assert(memcmp(fido_assert_authdata_ptr(a, 0), blob, blob_len) == 0);
	assert(fido_assert_authdata_raw_len(a, 0) == payload_len);
	assert(memcmp(fido_assert_authdata_raw_ptr(a, 0), payload,
	    payload_len) == 0);

	/* the raw variant must behave identically */
	assert(fido_assert_set_authdata_raw(a, 0, payload,
	    payload_len) == FIDO_OK);
	assert(fido_assert_flags(a, 0) == FLAGS_UP);

	fido_assert_free(&a);
	free(blob);
	free(payload);
}

/* Reserved flag bits must be rejected and must not leave state behind. */
static void
assert_reserved_flags(uint8_t flags)
{
	fido_assert_t	*a;
	unsigned char	*payload;
	unsigned char	*blob;
	size_t		 payload_len, blob_len;

	payload = assert_payload(flags, &payload_len);
	blob = cbor_wrap(payload, payload_len, &blob_len);

	a = fido_assert_new();
	assert(a != NULL);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);
	assert(fido_assert_set_authdata(a, 0, blob, blob_len) ==
	    FIDO_ERR_INVALID_ARGUMENT);
	assert_clean_state(a, 0);

	assert(fido_assert_set_authdata_raw(a, 0, payload,
	    payload_len) == FIDO_ERR_INVALID_ARGUMENT);
	assert_clean_state(a, 0);

	fido_assert_free(&a);
	free(blob);
	free(payload);
}

/* Trailing bytes after a complete payload must be rejected. */
static void
assert_trailing_bytes(int raw)
{
	fido_assert_t	*a;
	unsigned char	*payload;
	unsigned char	*blob;
	size_t		 payload_len, blob_len;

	payload = assert_payload(FLAGS_UP, &payload_len);
	assert((payload = realloc(payload, payload_len + 1)) != NULL);
	payload[payload_len++] = 0x00; /* stray byte */
	blob = cbor_wrap(payload, payload_len, &blob_len);

	a = fido_assert_new();
	assert(a != NULL);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);

	if (raw)
		assert(fido_assert_set_authdata_raw(a, 0, payload,
		    payload_len) == FIDO_ERR_INVALID_ARGUMENT);
	else
		assert(fido_assert_set_authdata(a, 0, blob,
		    blob_len) == FIDO_ERR_INVALID_ARGUMENT);
	assert_clean_state(a, 0);

	fido_assert_free(&a);
	free(blob);
	free(payload);
}

/* An extension flag without the matching extensions map must fail. */
static void
assert_dangling_ext_flag(void)
{
	fido_assert_t	*a;
	unsigned char	*payload;
	unsigned char	*blob;
	size_t		 payload_len, blob_len;

	payload = assert_payload(FLAGS_EXTDATA, &payload_len);
	blob = cbor_wrap(payload, payload_len, &blob_len);

	a = fido_assert_new();
	assert(a != NULL);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);
	assert(fido_assert_set_authdata(a, 0, blob, blob_len) ==
	    FIDO_ERR_INVALID_ARGUMENT);
	assert_clean_state(a, 0);

	/* once the map is present, the same payload is valid */
	payload = append_extensions(payload, &payload_len);
	free(blob);
	blob = cbor_wrap(payload, payload_len, &blob_len);
	assert(fido_assert_set_authdata(a, 0, blob, blob_len) == FIDO_OK);
	assert(fido_assert_flags(a, 0) == FLAGS_EXTDATA);

	fido_assert_free(&a);
	free(blob);
	free(payload);
}

/*
 * A failed decode must not poison the object: setting a valid payload after a
 * rejected one must succeed, and vice-versa.
 */
static void
assert_recovery_after_failure(void)
{
	fido_assert_t	*a;
	unsigned char	*good_payload, *bad_payload;
	unsigned char	*good_blob, *bad_blob;
	size_t		 good_len, bad_len, good_blob_len, bad_blob_len;

	good_payload = assert_payload(FLAGS_UP, &good_len);
	good_blob = cbor_wrap(good_payload, good_len, &good_blob_len);

	bad_payload = assert_payload(FLAGS_UP, &bad_len);
	assert((bad_payload = realloc(bad_payload, bad_len + 1)) != NULL);
	bad_payload[bad_len++] = 0x00;
	bad_blob = cbor_wrap(bad_payload, bad_len, &bad_blob_len);

	a = fido_assert_new();
	assert(a != NULL);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);

	assert(fido_assert_set_authdata(a, 0, bad_blob, bad_blob_len) ==
	    FIDO_ERR_INVALID_ARGUMENT);
	assert_clean_state(a, 0);
	assert(fido_assert_set_authdata(a, 0, good_blob,
	    good_blob_len) == FIDO_OK);
	assert(fido_assert_flags(a, 0) == FLAGS_UP);
	assert(fido_assert_set_authdata(a, 0, bad_blob, bad_blob_len) ==
	    FIDO_ERR_INVALID_ARGUMENT);
	assert_clean_state(a, 0);
	assert(fido_assert_set_authdata(a, 0, good_blob,
	    good_blob_len) == FIDO_OK);
	assert(fido_assert_flags(a, 0) == FLAGS_UP);

	fido_assert_free(&a);
	free(good_blob);
	free(bad_blob);
	free(good_payload);
	free(bad_payload);
}

/*
 * A minimal attested credential: 16 zero aaguid bytes, a zero-length
 * credential id and a well-formed (if cryptographically trivial) ES256 COSE
 * key map. The COSE key is assembled programmatically so that the two 32-byte
 * coordinates cannot be miscounted.
 */
static unsigned char *
cred_payload(uint8_t flags, size_t *out_len)
{
	/* COSE ES256 key map in canonical CTAP2 CBOR key order: kty (1),
	 * alg (3), then crv (-1), x (-2), y (-3); coordinates are zeros. */
	static const unsigned char cose_hdr[] = {
		0xa5, 0x01, 0x02,	/* map(5), kty = EC2 */
		0x03, 0x26,		/* alg = ES256 (-7) */
		0x20, 0x01,		/* crv (-1) = P-256 */
		0x21, 0x58, 0x20,	/* x (-2): 32-byte bytestring */
	};
	static const unsigned char cose_y[] = {
		0x22, 0x58, 0x20,	/* y (-3): 32-byte bytestring */
	};
	size_t		 cose_len;
	unsigned char	*p;
	size_t		 l;

	cose_len = sizeof(cose_hdr) + 32 + sizeof(cose_y) + 32;
	l = AUTHDATA_LEN + 18 + cose_len;
	assert((p = calloc(1, l)) != NULL);
	p[32] = flags;
	/* aaguid (16 bytes) and credential id length (2 bytes) stay zero. */
	memcpy(p + AUTHDATA_LEN + 18, cose_hdr, sizeof(cose_hdr));
	memcpy(p + AUTHDATA_LEN + 18 + sizeof(cose_hdr) + 32, cose_y,
	    sizeof(cose_y));
	/* both 32-byte coordinates remain zero from calloc */
	*out_len = l;

	return (p);
}

static void
cred_clean_state(const fido_cred_t *c)
{
	assert(fido_cred_authdata_ptr(c) == NULL);
	assert(fido_cred_authdata_len(c) == 0);
	assert(fido_cred_authdata_raw_ptr(c) == NULL);
	assert(fido_cred_authdata_raw_len(c) == 0);
	assert(fido_cred_flags(c) == 0);
	assert(fido_cred_id_len(c) == 0);
	assert(fido_cred_id_ptr(c) == NULL);
}

/* Credential-side strict checks through the public credential API. */
static void
cred_strict(void)
{
	fido_cred_t	*c;
	unsigned char	*payload, *blob;
	size_t		 payload_len, blob_len;

	/* valid attested credential payload */
	payload = cred_payload(FLAGS_ATTCRED | FLAGS_UP, &payload_len);
	blob = cbor_wrap(payload, payload_len, &blob_len);

	c = fido_cred_new();
	assert(c != NULL);
	assert(fido_cred_set_type(c, COSE_ES256) == FIDO_OK);
	assert(fido_cred_set_authdata(c, blob, blob_len) == FIDO_OK);
	assert(fido_cred_flags(c) == (FLAGS_ATTCRED | FLAGS_UP));
	assert(fido_cred_id_len(c) == 0);
	fido_cred_free(&c);
	free(blob);

	/* reserved flag bits */
	payload[32] = FLAGS_ATTCRED | FLAGS_RESERVED;
	blob = cbor_wrap(payload, payload_len, &blob_len);
	c = fido_cred_new();
	assert(c != NULL);
	assert(fido_cred_set_type(c, COSE_ES256) == FIDO_OK);
	assert(fido_cred_set_authdata(c, blob, blob_len) ==
	    FIDO_ERR_INVALID_ARGUMENT);
	cred_clean_state(c);

	/* trailing bytes */
	assert((payload = realloc(payload, payload_len + 1)) != NULL);
	payload[payload_len++] = 0x00;
	free(blob);
	blob = cbor_wrap(payload, payload_len, &blob_len);
	assert(fido_cred_set_authdata(c, blob, blob_len) ==
	    FIDO_ERR_INVALID_ARGUMENT);
	cred_clean_state(c);

	/* recovery: the original, valid payload must still decode */
	payload_len--;
	free(blob);
	payload[32] = FLAGS_ATTCRED | FLAGS_UP;
	blob = cbor_wrap(payload, payload_len, &blob_len);
	assert(fido_cred_set_authdata(c, blob, blob_len) == FIDO_OK);
	assert(fido_cred_flags(c) == (FLAGS_ATTCRED | FLAGS_UP));

	fido_cred_free(&c);
	free(blob);
	free(payload);
}

/* Repeated failed decodes on the same object must keep it clean. */
static void
repeated_failures(void)
{
	fido_assert_t	*a;
	unsigned char	*payload;
	unsigned char	*blob;
	size_t		 payload_len, blob_len;
	int		 i;

	payload = assert_payload(FLAGS_UP | FLAGS_RESERVED, &payload_len);
	blob = cbor_wrap(payload, payload_len, &blob_len);

	a = fido_assert_new();
	assert(a != NULL);
	assert(fido_assert_set_count(a, 1) == FIDO_OK);

	for (i = 0; i < 16; i++) {
		assert(fido_assert_set_authdata(a, 0, blob, blob_len) ==
		    FIDO_ERR_INVALID_ARGUMENT);
		assert_clean_state(a, 0);
	}

	fido_assert_free(&a);
	free(blob);
	free(payload);
}

int
main(void)
{
	assert_valid();

	assert_reserved_flags(FLAGS_RESERVED);
	assert_reserved_flags(FLAGS_UP | FLAGS_RESERVED);
	assert_reserved_flags(0x02); /* a single reserved bit */
	assert_reserved_flags(0x20);

	assert_trailing_bytes(0);
	assert_trailing_bytes(1);

	assert_dangling_ext_flag();
	assert_recovery_after_failure();
	cred_strict();
	repeated_failures();

	return (0);
}
