/*
 * Copyright (c) 2024 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Malicious-device regression tests for the CTAPHID frame reassembly
 * logic in fido_rx() (see src/io.c). A scriptable I/O backend feeds
 * hand-crafted HID reports to the parser without any real authenticator
 * being involved. Every test asserts that malformed input is rejected,
 * that no out-of-bounds write occurs and that frames belonging to a
 * different message never get spliced into a partial one.
 */

#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _FIDO_INTERNAL

#include <fido.h>

#define REPORT_LEN	CTAP_MAX_REPORT_LEN			/* 64 */
#define INIT_DATA_LEN	(REPORT_LEN - CTAP_INIT_HEADER_LEN)	/* 57 */
#define CONT_DATA_LEN	(REPORT_LEN - CTAP_CONT_HEADER_LEN)	/* 59 */

#define TEST_CMD	CTAP_CMD_PING /* parser only checks the opcode */

#define SCRIPT_MAX	16 /* maximum number of reports in one script */

/*
 * The parser compares cid fields as raw, packed uint32 values (no
 * byte-swap), so channel ids are built from their on-the-wire bytes
 * rather than as host-order integers.
 */
static uint32_t test_cid;
static uint32_t other_cid;

static uint32_t
cid_from_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	const uint8_t	 raw[4] = { a, b, c, d };
	uint32_t	 cid;

	memcpy(&cid, raw, sizeof(cid));

	return (cid);
}

static void
cid_to_bytes(uint32_t cid, uint8_t *raw)
{
	memcpy(raw, &cid, sizeof(cid));
}

/*
 * A single report served by the mock device. When "short" is non-zero,
 * the read callback returns fewer bytes than the host asked for; when
 * "fail" is non-zero, the read callback errors out outright. Both model
 * a device that truncates or aborts a continuation in the middle of a
 * message.
 */
struct report {
	uint8_t	 body[REPORT_LEN];
	size_t	 len;
	int	 short_read;
	int	 fail_read;
};

struct script {
	struct report	 report[SCRIPT_MAX];
	size_t		 len;
	size_t		 idx;
	int		 opened;
};

static struct script mock;
static int fake_dev_handle;

static void *
mock_open(const char *path)
{
	(void)path;

	assert(mock.opened == 0);
	mock.opened = 1;

	return (&fake_dev_handle);
}

static void
mock_close(void *handle)
{
	assert(handle == &fake_dev_handle);
	assert(mock.opened == 1);
	mock.opened = 0;
}

static int
mock_read(void *handle, unsigned char *ptr, size_t len, int ms)
{
	struct report	*r;

	(void)ms;

	assert(handle == &fake_dev_handle);
	assert(ptr != NULL);
	assert(len == REPORT_LEN);

	if (mock.idx >= mock.len)
		return (-1); /* device went silent mid-message */

	r = &mock.report[mock.idx++];

	if (r->fail_read)
		return (-1);

	if (r->len > len)
		return (-1);

	memcpy(ptr, r->body, r->len);

	if (r->short_read)
		return ((int)(r->len / 2));

	return ((int)r->len);
}

static int
mock_write(void *handle, const unsigned char *ptr, size_t len)
{
	assert(handle == &fake_dev_handle);
	assert(ptr != NULL);
	assert(len >= 1 && len <= REPORT_LEN + 1);

	return ((int)len);
}

static void
script_reset(void)
{
	size_t opened = mock.opened;

	memset(&mock, 0, sizeof(mock));
	mock.opened = opened; /* keep the open/close lifecycle intact */
}

static struct report *
script_add(void)
{
	assert(mock.len < SCRIPT_MAX);

	return (&mock.report[mock.len++]);
}

/*
 * Assemble an initialization frame: cid, 0x80|cmd, 16-bit declared
 * payload length and up to INIT_DATA_LEN payload bytes.
 */
static struct report *
frame_init(uint32_t cid, uint8_t cmd, uint16_t bcnt,
    const uint8_t *payload, size_t payload_len)
{
	struct report	*r = script_add();

	assert(payload_len <= INIT_DATA_LEN);

	memset(r, 0, sizeof(*r));
	r->len = REPORT_LEN;
	cid_to_bytes(cid, r->body);
	r->body[4] = CTAP_FRAME_INIT | cmd;
	r->body[5] = (uint8_t)(bcnt >> 8);
	r->body[6] = (uint8_t)bcnt;
	if (payload_len)
		memcpy(&r->body[7], payload, payload_len);

	return (r);
}

/* Assemble a continuation frame: cid, sequence number and payload. */
static struct report *
frame_cont(uint32_t cid, uint8_t seq, const uint8_t *payload,
    size_t payload_len)
{
	struct report	*r = script_add();

	assert(payload_len <= CONT_DATA_LEN);

	memset(r, 0, sizeof(*r));
	r->len = REPORT_LEN;
	cid_to_bytes(cid, r->body);
	r->body[4] = seq;
	if (payload_len)
		memcpy(&r->body[5], payload, payload_len);

	return (r);
}

static fido_dev_t *
open_mock_dev(void)
{
	fido_dev_t	*dev = NULL;
	fido_dev_io_t	 io;

	assert((dev = fido_dev_new()) != NULL);

	memset(&io, 0, sizeof(io));
	io.open = mock_open;
	io.close = mock_close;
	io.read = mock_read;
	io.write = mock_write;
	assert(fido_dev_set_io_functions(dev, &io) == FIDO_OK);

	/*
	 * Skip the CTAPHID_INIT exchange and put the device directly in
	 * the state fido_dev_open_rx() would leave it in: an owned I/O
	 * backend uses full-size reports and a negotiated channel id.
	 */
	assert((dev->io_handle = dev->io.open("mock")) != NULL);
	dev->rx_len = REPORT_LEN;
	dev->tx_len = REPORT_LEN;
	dev->cid = test_cid;
	dev->timeout_ms = -1;

	return (dev);
}

static void
close_mock_dev(fido_dev_t **dev_p)
{
	fido_dev_t *dev;

	assert(dev_p != NULL);
	dev = *dev_p;
	assert(dev != NULL);
	assert(fido_dev_close(dev) == FIDO_OK);
	fido_dev_free(dev_p);
}

/* Fill a payload pattern so reassembled bytes can be recognised. */
static void
fill_pattern(uint8_t *buf, size_t len, uint8_t base)
{
	for (size_t i = 0; i < len; i++)
		buf[i] = (uint8_t)(base + (uint8_t)i);
}

/*
 * Drive fido_rx() once against the script currently installed in the
 * mock backend and check that the bytes beyond "want_len" are left
 * untouched, i.e. that a frame never spills past the declared message.
 */
static void
run_rx(const char *name, fido_dev_t *dev, uint8_t cmd, uint8_t *buf,
    size_t buf_len, int want_rc, size_t want_len)
{
	const uint8_t canary = 0xa5;
	int		ms = -1;
	int		rc;

	memset(buf, canary, buf_len);
	rc = fido_rx(dev, cmd, buf, buf_len, &ms);

	if (rc != want_rc) {
		fprintf(stderr, "%s: fido_rx returned %d, want %d\n", name, rc,
		    want_rc);
		assert(0);
	}

	if (rc >= 0) {
		assert((size_t)rc == want_len);
		for (size_t i = want_len; i < buf_len; i++)
			assert(buf[i] == canary);
	}
}

/* A legal single-frame message must still parse. */
static void
valid_single_frame(void)
{
	uint8_t		 payload[INIT_DATA_LEN];
	uint8_t		 buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, sizeof(payload), 0x10);
	frame_init(test_cid, TEST_CMD, (uint16_t)sizeof(payload), payload,
	    sizeof(payload));

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf),
	    (int)sizeof(payload), sizeof(payload));
	assert(memcmp(buf, payload, sizeof(payload)) == 0);
	close_mock_dev(&dev);
	script_reset();
}

/* A legal multi-frame message must reassemble byte-for-byte. */
static void
valid_multi_frame(void)
{
	const size_t	msg_len = INIT_DATA_LEN + 2 * CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0x40);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	frame_cont(test_cid, 1, payload + INIT_DATA_LEN + CONT_DATA_LEN,
	    CONT_DATA_LEN);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), (int)msg_len,
	    msg_len);
	assert(memcmp(buf, payload, msg_len) == 0);
	close_mock_dev(&dev);
	script_reset();
}

/* A legal final continuation shorter than a full report must be honoured. */
static void
valid_multi_frame_short_final(void)
{
	const size_t	msg_len = INIT_DATA_LEN + CONT_DATA_LEN + 7;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0x70);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	frame_cont(test_cid, 1, payload + INIT_DATA_LEN + CONT_DATA_LEN,
	    msg_len - INIT_DATA_LEN - CONT_DATA_LEN);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), (int)msg_len,
	    msg_len);
	assert(memcmp(buf, payload, msg_len) == 0);
	close_mock_dev(&dev);
	script_reset();
}

/* Continuation frames arriving out of sequence must be rejected. */
static void
bad_out_of_order_seq(void)
{
	const size_t	msg_len = INIT_DATA_LEN + 2 * CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0x10);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 1, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN + CONT_DATA_LEN,
	    CONT_DATA_LEN);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/* A repeated sequence number (0,0 instead of 0,1) must be rejected. */
static void
bad_duplicate_seq(void)
{
	const size_t	msg_len = INIT_DATA_LEN + 2 * CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0x20);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN + CONT_DATA_LEN,
	    CONT_DATA_LEN);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/* A continuation frame on another channel must not join the message. */
static void
bad_channel_switch(void)
{
	const size_t	msg_len = INIT_DATA_LEN + CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0x30);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(other_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	/* a well-formed frame must never be consumed after the error */
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	assert(mock.idx == 2); /* the foreign frame ended the exchange */
	close_mock_dev(&dev);
	script_reset();
}

/* An initialization frame from another channel must be rejected. */
static void
bad_preamble_cid(void)
{
	uint8_t		 payload[16];
	uint8_t		 buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, sizeof(payload), 0x50);
	frame_init(other_cid, TEST_CMD, (uint16_t)sizeof(payload), payload,
	    sizeof(payload));

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/*
 * A declared payload length larger than the caller's buffer must be
 * rejected before any continuation frame is read.
 */
static void
bad_length_overflow(void)
{
	uint8_t		 payload[INIT_DATA_LEN];
	uint8_t		 buf[64];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, sizeof(payload), 0x60);
	frame_init(test_cid, TEST_CMD, UINT16_MAX, payload, sizeof(payload));
	/* never consumed: the preamble alone must reject the message */
	frame_cont(test_cid, 0, NULL, 0);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	assert(mock.idx == 1); /* rejected straight from the preamble */
	close_mock_dev(&dev);
	script_reset();
}

/*
 * The largest possible declared length (65535) must never cause an
 * out-of-bounds write even when the buffer is generously sized: the
 * exhausted script aborts the exchange first.
 */
static void
bad_huge_declared_length(void)
{
	uint8_t		 payload[INIT_DATA_LEN];
	uint8_t		*buf;
	fido_dev_t	*dev;

	assert((buf = malloc(FIDO_MAXMSG)) != NULL);

	script_reset();
	fill_pattern(payload, sizeof(payload), 0x80);
	frame_init(test_cid, TEST_CMD, UINT16_MAX, payload, sizeof(payload));

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, FIDO_MAXMSG, -1, 0);
	assert(mock.idx == 1); /* only the preamble was consumed */
	close_mock_dev(&dev);
	free(buf);
	script_reset();
}

/* A message whose last continuation never arrives stays incomplete. */
static void
bad_truncated_continuation(void)
{
	const size_t	msg_len = INIT_DATA_LEN + 2 * CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0x90);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	/* device stops here: the second continuation is missing */

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/* A short read in the middle of a message must fail the reassembly. */
static void
bad_short_read(void)
{
	const size_t	msg_len = INIT_DATA_LEN + CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	struct report	*r;
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0xa0);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	r = frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	r->short_read = 1;

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/* An outright read error mid-message must fail the reassembly. */
static void
bad_failed_read(void)
{
	const size_t	msg_len = INIT_DATA_LEN + CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	struct report	*r;
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0xb0);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	r = frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	r->fail_read = 1;

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/* A wrong command in the preamble must be rejected. */
static void
bad_wrong_command(void)
{
	uint8_t		 payload[16];
	uint8_t		 buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, sizeof(payload), 0xc0);
	frame_init(test_cid, CTAP_CMD_WINK, (uint16_t)sizeof(payload),
	    payload, sizeof(payload));

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	close_mock_dev(&dev);
	script_reset();
}

/*
 * A foreign init frame that interrupts a partial message must not be
 * spliced into it: the parser only expects a continuation and treats
 * the stray init as a channel/sequence mismatch.
 */
static void
bad_init_instead_of_cont(void)
{
	const size_t	msg_len = INIT_DATA_LEN + CONT_DATA_LEN;
	uint8_t		payload[msg_len];
	uint8_t		buf[256];
	fido_dev_t	*dev;

	script_reset();
	fill_pattern(payload, msg_len, 0xd0);

	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	/* device restarts a brand-new message where seq 0 was expected */
	frame_init(test_cid, TEST_CMD, (uint16_t)INIT_DATA_LEN, payload,
	    INIT_DATA_LEN);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), -1, 0);
	assert(mock.idx == 2);
	close_mock_dev(&dev);
	script_reset();
}

/* A zero-length message is a legal single-frame reply. */
static void
valid_zero_length(void)
{
	uint8_t		 buf[64];
	fido_dev_t	*dev;

	script_reset();
	frame_init(test_cid, TEST_CMD, 0, NULL, 0);

	dev = open_mock_dev();
	run_rx(__func__, dev, TEST_CMD, buf, sizeof(buf), 0, 0);
	close_mock_dev(&dev);
	script_reset();
}

/*
 * After a failed exchange the parser must carry no state into the next
 * one: a legal message following a malicious one still reassembles.
 */
static void
recovery_after_error(void)
{
	const size_t	msg_len = INIT_DATA_LEN + 2 * CONT_DATA_LEN;
	uint8_t		 payload[msg_len];
	uint8_t		 bad_buf[256];
	uint8_t		 good_buf[256];
	fido_dev_t	*dev;
	int		 ms = -1;

	dev = open_mock_dev();

	/* 1. malicious device: duplicated sequence number */
	script_reset();
	fill_pattern(payload, msg_len, 0xe0);
	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN + CONT_DATA_LEN,
	    CONT_DATA_LEN);
	assert(fido_rx(dev, TEST_CMD, bad_buf, sizeof(bad_buf), &ms) == -1);
	script_reset();

	/* 2. well-behaved device on the same channel */
	fill_pattern(payload, msg_len, 0x01);
	frame_init(test_cid, TEST_CMD, (uint16_t)msg_len, payload,
	    INIT_DATA_LEN);
	frame_cont(test_cid, 0, payload + INIT_DATA_LEN, CONT_DATA_LEN);
	frame_cont(test_cid, 1, payload + INIT_DATA_LEN + CONT_DATA_LEN,
	    CONT_DATA_LEN);
	run_rx(__func__, dev, TEST_CMD, good_buf, sizeof(good_buf),
	    (int)msg_len, msg_len);
	assert(memcmp(good_buf, payload, msg_len) == 0);

	close_mock_dev(&dev);
	script_reset();
}

int
main(void)
{
	fido_init(0);

	/* wire-order bytes; the parser compares cid as a packed uint32 */
	test_cid = cid_from_bytes(0x00, 0x22, 0x00, 0x02);
	other_cid = cid_from_bytes(0xde, 0xad, 0xbe, 0xef);

	/* legal traffic keeps working */
	valid_single_frame();
	valid_multi_frame();
	valid_multi_frame_short_final();
	valid_zero_length();

	/* malicious device inputs */
	bad_out_of_order_seq();
	bad_duplicate_seq();
	bad_channel_switch();
	bad_preamble_cid();
	bad_length_overflow();
	bad_huge_declared_length();
	bad_truncated_continuation();
	bad_short_read();
	bad_failed_read();
	bad_wrong_command();
	bad_init_instead_of_cont();

	/* parser state must not leak across exchanges */
	recovery_after_error();

	exit(0);
}
