/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/printk.h>

#include <stsephyr/stsafe_a120.h>

LOG_MODULE_REGISTER(basic, LOG_LEVEL_INF);

static const struct device *const stsafe = DEVICE_DT_GET_ONE(st_stsafe_a120);

int main(void)
{
	static const uint8_t request[] = "STSEphyr/A120";
	uint8_t response[sizeof(request)] = {0};
	stse_Handler_t *handler;
	stse_ReturnCode_t status;
	int ret;

	if (!device_is_ready(stsafe)) {
		LOG_ERR("STSAFE-A120 device is not ready");
		return 0;
	}

	ret = stsephyr_acquire(stsafe, K_MSEC(CONFIG_STSEPHYR_LOCK_TIMEOUT_MS), &handler);
	if (ret != 0) {
		LOG_ERR("could not acquire STSAFE-A120 (%d)", ret);
		return 0;
	}

	status = stse_device_echo(handler, (uint8_t *)request, response, sizeof(request));
	stsephyr_release(stsafe);

	if (status != STSE_OK) {
		LOG_ERR("STSELib echo failed (0x%x)", status);
		return 0;
	}
	if (memcmp(request, response, sizeof(request)) != 0) {
		LOG_ERR("STSAFE-A120 echo response mismatch");
		return 0;
	}

	LOG_INF("STSAFE-A120 echo successful");
	printk("PASS: basic\n");
	return 0;
}
