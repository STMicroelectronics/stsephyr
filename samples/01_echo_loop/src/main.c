/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sends random messages of random length to the STSAFE-A120 echo command and
 * checks the responses. Long messages exercise the I2C frame segmentation.
 */

#include "sample_common.h"

#include <string.h>

#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>

#define ITERATIONS	 10U
#define MAX_MESSAGE_SIZE 500U

int main(void)
{
	static uint8_t request[MAX_MESSAGE_SIZE];
	static uint8_t response[MAX_MESSAGE_SIZE];
	stse_Handler_t *handler;

	printk("STSAFE-A120 echo loop\n");
	if (sample_open(&handler) != 0) {
		return 0;
	}

	for (unsigned int i = 1U; i <= ITERATIONS; i++) {
		uint16_t length;

		if (sys_csrand_get(&length, sizeof(length)) != 0 ||
		    sys_csrand_get(request, sizeof(request)) != 0) {
			printk("FAIL: host random generator\n");
			goto out;
		}
		/* Always include the 1-byte and maximum-size edge cases. */
		if (i == 1U) {
			length = 1U;
		} else if (i == ITERATIONS) {
			length = MAX_MESSAGE_SIZE;
		} else {
			length = 1U + length % MAX_MESSAGE_SIZE;
		}
		memset(response, 0, length);

		if (stse_device_echo(handler, request, response, length) != STSE_OK ||
		    memcmp(request, response, length) != 0) {
			printk("FAIL: echo of %u bytes\n", length);
			goto out;
		}
		printk("Echo %2u/%u: %3u bytes OK\n", i, ITERATIONS, length);
	}

	printk("PASS: 01_echo_loop\n");
out:
	sample_close();
	return 0;
}
