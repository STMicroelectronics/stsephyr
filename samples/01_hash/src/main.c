/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hashes a random message in the STSAFE-A120 and on the MCU (PSA Crypto), then
 * compares the digests. The algorithm is selected in this sample's Kconfig.
 */

#include "sample_common.h"

#include <string.h>

#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>

#if defined(CONFIG_SAMPLE_HASH_SHA3_256)
#define HASH_ALGORITHM STSE_SHA3_256
#define HASH_NAME      "SHA3-256"
#define HASH_SIZE      32U
#elif defined(CONFIG_SAMPLE_HASH_SHA3_384)
#define HASH_ALGORITHM STSE_SHA3_384
#define HASH_NAME      "SHA3-384"
#define HASH_SIZE      48U
#elif defined(CONFIG_SAMPLE_HASH_SHA3_512)
#define HASH_ALGORITHM STSE_SHA3_512
#define HASH_NAME      "SHA3-512"
#define HASH_SIZE      64U
#else
#define HASH_ALGORITHM STSE_SHA_256
#define HASH_NAME      "SHA-256"
#define HASH_SIZE      32U
#endif

int main(void)
{
	uint8_t message[128];
	uint8_t host_digest[HASH_SIZE];
	uint8_t device_digest[HASH_SIZE];
	uint16_t host_length = sizeof(host_digest);
	uint16_t device_length = sizeof(device_digest);
	stse_Handler_t *handler;

	printk("STSAFE-A120 %s hash\n", HASH_NAME);
	if (sys_csrand_get(message, sizeof(message)) != 0) {
		printk("FAIL: host random generator\n");
		return 0;
	}
	if (sample_open(&handler) != 0) {
		return 0;
	}

	if (sample_check("Hash on the STSAFE-A120",
			 stse_compute_hash(handler, HASH_ALGORITHM, message, sizeof(message),
					   device_digest, &device_length)) != 0 ||
	    sample_check("Hash on the MCU",
			 stse_platform_hash_compute(HASH_ALGORITHM, message, sizeof(message),
						    host_digest, &host_length)) != 0) {
		goto out;
	}
	sample_print_hex("STSAFE-A120 digest", device_digest, device_length);
	sample_print_hex("MCU digest", host_digest, host_length);

	if (device_length != HASH_SIZE || host_length != HASH_SIZE ||
	    memcmp(device_digest, host_digest, HASH_SIZE) != 0) {
		printk("FAIL: digests differ\n");
		goto out;
	}
	printk("PASS: 01_hash\n");

out:
	sample_close();
	return 0;
}
