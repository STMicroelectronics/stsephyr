/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sample_common.h"

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

static const struct device *const stsafe = DEVICE_DT_GET_ONE(st_stsafe_a120);

int sample_open(stse_Handler_t **handler)
{
	int ret;

	if (!device_is_ready(stsafe)) {
		printk("FAIL: STSAFE-A120 device is not ready\n");
		return -ENODEV;
	}

	ret = stsephyr_acquire(stsafe, K_MSEC(CONFIG_STSEPHYR_LOCK_TIMEOUT_MS), handler);
	if (ret != 0) {
		printk("FAIL: cannot acquire STSAFE-A120 (%d)\n", ret);
	}
	return ret;
}

void sample_close(void)
{
	stsephyr_release(stsafe);
}

int sample_check(const char *operation, stse_ReturnCode_t status)
{
	if (status != STSE_OK) {
		printk("FAIL: %s returned STSELib status 0x%04X\n", operation, status);
		return stsephyr_stse_to_errno(status);
	}

	printk("%s: OK\n", operation);
	return 0;
}

void sample_print_hex(const char *label, const uint8_t *data, size_t length)
{
	printk("%s (%u bytes):", label, (unsigned int)length);
	for (size_t i = 0; i < length; i++) {
		printk("%s%02X", (i % 16U) == 0U ? "\n  " : " ", data[i]);
	}
	printk("\n");
}
