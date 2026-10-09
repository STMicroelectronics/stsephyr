/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Known-answer tests for the PSA Crypto platform callbacks.
 */

#include <string.h>
#include <stselib.h>
#include <zephyr/logging/log.h>
#include <zephyr/ztest.h>

/* The callbacks are built without the driver, which normally registers this module. */
LOG_MODULE_REGISTER(stsephyr, CONFIG_STSEPHYR_LOG_LEVEL);

static void *crypto_setup(void)
{
	zassert_equal(stse_platform_crypto_init(), STSE_OK);
	return NULL;
}

ZTEST(stsephyr_crypto, test_sha256)
{
	uint8_t input[] = "abc";
	const uint8_t expected[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
		0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
		0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	uint8_t digest[32];
	uint16_t length = sizeof(digest);

	zassert_equal(stse_platform_hash_compute(STSE_SHA_256, input, 3, digest, &length), STSE_OK);
	zassert_equal(length, sizeof(expected));
	zassert_mem_equal(digest, expected, sizeof(expected));
}

ZTEST(stsephyr_crypto, test_cmac_stream_and_reject)
{
	/* RFC 4493, example 2. */
	uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	uint8_t input[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
			   0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
	const uint8_t expected[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
				    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
	uint8_t tag[16];
	uint8_t length;

	zassert_equal(stse_platform_aes_cmac_init(key, sizeof(key), sizeof(tag)), STSE_OK);
	zassert_equal(stse_platform_aes_cmac_append(input, 7), STSE_OK);
	zassert_equal(stse_platform_aes_cmac_append(input + 7, sizeof(input) - 7), STSE_OK);
	zassert_equal(stse_platform_aes_cmac_compute_finish(tag, &length), STSE_OK);
	zassert_equal(length, sizeof(tag));
	zassert_mem_equal(tag, expected, sizeof(tag));
	tag[0] ^= 1;
	zassert_equal(stse_platform_aes_cmac_init(key, sizeof(key), sizeof(tag)), STSE_OK);
	zassert_equal(stse_platform_aes_cmac_append(input, sizeof(input)), STSE_OK);
	zassert_equal(stse_platform_aes_cmac_verify_finish(tag),
		      STSE_PLATFORM_AES_CMAC_VERIFY_ERROR);
}

ZTEST(stsephyr_crypto, test_hkdf_sha256)
{
	/* RFC 5869, test case 1 exercises more than one expand block. */
	uint8_t ikm[22];
	uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
	uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
	const uint8_t expected[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
		0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
		0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	};
	uint8_t output[sizeof(expected)];

	memset(ikm, 0x0b, sizeof(ikm));
	zassert_equal(stse_platform_hmac_sha256_compute(salt, sizeof(salt), ikm, sizeof(ikm), info,
							sizeof(info), output, sizeof(output)),
		      STSE_OK);
	zassert_mem_equal(output, expected, sizeof(output));
	zassert_equal(
		stse_platform_hmac_sha256_expand(ikm, sizeof(ikm), NULL, 1, output, sizeof(output)),
		STSE_PLATFORM_INVALID_PARAMETER);
}

ZTEST(stsephyr_crypto, test_key_wrap_in_place)
{
	/* RFC 3394, section 4.1. */
	uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t buffer[24] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	const uint8_t expected[] = {
		0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8,
		0xfb, 0x5a, 0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
	};
	uint32_t length = sizeof(buffer);

	zassert_equal(stse_platform_nist_kw_encrypt(buffer, 16, key, sizeof(key), buffer, &length),
		      STSE_OK);
	zassert_equal(length, sizeof(buffer));
	zassert_mem_equal(buffer, expected, sizeof(buffer));
}

ZTEST(stsephyr_crypto, test_aes_reject_missing_cbc_iv)
{
	uint8_t key[16] = {0};
	uint8_t block[16] = {0};
	uint16_t length = sizeof(block);

	zassert_equal(stse_platform_aes_cbc_enc(block, sizeof(block), NULL, key, sizeof(key), block,
						&length),
		      STSE_PLATFORM_INVALID_PARAMETER);
}

ZTEST_SUITE(stsephyr_crypto, NULL, crypto_setup, NULL, NULL, NULL);
