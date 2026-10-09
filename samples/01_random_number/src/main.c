/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reads random bytes from the STSAFE-A120 random number generator.
 */

#include "sample_common.h"

#include <zephyr/sys/printk.h>

int main(void)
{
	uint8_t random[64];
	stse_Handler_t *handler;

	printk("STSAFE-A120 random number generation\n");
	if (sample_open(&handler) != 0) {
		return 0;
	}

	if (sample_check("Generate 64 random bytes",
			 stse_generate_random(handler, random, sizeof(random))) == 0) {
		sample_print_hex("Random data", random, sizeof(random));
		printk("PASS: 01_random_number\n");
	}

	sample_close();
	return 0;
}
