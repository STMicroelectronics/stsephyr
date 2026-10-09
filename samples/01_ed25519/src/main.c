/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies an RFC 8032 Ed25519 test vector in the STSAFE-A120 and on the MCU,
 * and checks that the MCU rejects a corrupted signature. No key is stored.
 */

#include "sample_common.h"

#include <string.h>

#include <zephyr/sys/printk.h>

/* RFC 8032, section 7.1, test 2 (one-byte message). */
static const uint8_t public_key[32] = {
	0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a,
	0xa7, 0x4d, 0x1b, 0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4,
	0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
};
static const uint8_t message[] = {0x72};
static const uint8_t signature[64] = {
	0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f,
	0x64, 0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76,
	0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99,
	0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae,
	0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
};

int main(void)
{
	uint8_t corrupted[sizeof(signature)];
	uint8_t valid = 0U;
	stse_Handler_t *handler;

	printk("STSAFE-A120 Ed25519 signature verification\n");
	if (sample_open(&handler) != 0) {
		return 0;
	}

	if (sample_check("Verify on the STSAFE-A120",
			 stse_ecc_verify_signature(handler, STSE_ECC_KT_ED25519, public_key,
						   signature, message, sizeof(message), 0U,
						   &valid)) != 0) {
		goto out;
	}
	if (valid != 1U) {
		printk("FAIL: STSAFE-A120 rejected the RFC 8032 signature\n");
		goto out;
	}

	if (sample_check("Verify on the MCU",
			 stse_platform_ecc_verify(STSE_ECC_KT_ED25519, public_key,
						  (uint8_t *)message, sizeof(message),
						  (uint8_t *)signature)) != 0) {
		goto out;
	}

	memcpy(corrupted, signature, sizeof(corrupted));
	corrupted[0] ^= 0x01U;
	if (stse_platform_ecc_verify(STSE_ECC_KT_ED25519, public_key, (uint8_t *)message,
				     sizeof(message), corrupted) == STSE_OK) {
		printk("FAIL: MCU accepted a corrupted signature\n");
		goto out;
	}
	printk("Corrupted signature rejected on the MCU: OK\n");
	printk("PASS: 01_ed25519\n");

out:
	sample_close();
	return 0;
}
