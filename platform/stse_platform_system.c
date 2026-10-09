/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>

#include "stsephyr_internal.h"

LOG_MODULE_DECLARE(stsephyr, CONFIG_STSEPHYR_LOG_LEVEL);

static const struct device *instances[CONFIG_STSEPHYR_MAX_INSTANCES];
K_MUTEX_DEFINE(stsephyr_library_lock);

int stsephyr_platform_register(const struct device *dev, uint8_t bus_id)
{
	if (dev == NULL || bus_id >= ARRAY_SIZE(instances) || instances[bus_id] != NULL) {
		return -EINVAL;
	}

	instances[bus_id] = dev;
	return 0;
}

const struct device *stsephyr_platform_get(uint8_t bus_id)
{
	if (bus_id >= ARRAY_SIZE(instances)) {
		return NULL;
	}

	return instances[bus_id];
}

int stsephyr_global_lock(k_timeout_t timeout)
{
	return k_mutex_lock(&stsephyr_library_lock, timeout);
}

void stsephyr_global_unlock(void)
{
	(void)k_mutex_unlock(&stsephyr_library_lock);
}

int stsephyr_set_reset(const struct device *dev, bool asserted)
{
	const struct stsephyr_config *config;

	if (dev == NULL) {
		return -EINVAL;
	}

	config = dev->config;
	return gpio_pin_set_dt(&config->reset, asserted ? 1 : 0);
}

int stsephyr_hw_reset(const struct device *dev)
{
	int ret;

	ret = stsephyr_set_reset(dev, true);
	if (ret != 0) {
		return ret;
	}

	k_msleep(CONFIG_STSEPHYR_RESET_ASSERT_MS);
	return stsephyr_set_reset(dev, false);
}

stse_ReturnCode_t stse_platform_delay_init(void)
{
	return STSE_OK;
}

void stse_platform_Delay_ms(PLAT_UI16 delay_val)
{
	k_msleep(delay_val);
}

stse_ReturnCode_t stse_platform_generate_random_init(void)
{
	uint32_t probe;

	if (sys_csrand_get(&probe, sizeof(probe)) != 0) {
		LOG_ERR("cryptographically secure random source is unavailable");
		return STSE_PLATFORM_SERVICES_INIT_ERROR;
	}

	return STSE_OK;
}

PLAT_UI32 stse_platform_generate_random(void)
{
	uint32_t value = 0U;

	if (sys_csrand_get(&value, sizeof(value)) != 0) {
		LOG_ERR("CSPRNG request failed");
		/* STSELib's random-word callback has no error return. Fail closed. */
		k_panic();
	}

	return value;
}

stse_ReturnCode_t stse_platform_power_init(void)
{
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_power_ctrl_init(void)
{
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_power_on(PLAT_UI8 busID, PLAT_UI8 devAddr)
{
	const struct device *dev = stsephyr_platform_get(busID);

	ARG_UNUSED(devAddr);
	if (dev == NULL || stsephyr_set_reset(dev, false) != 0) {
		return STSE_PLATFORM_POWER_ERROR;
	}

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_power_off(PLAT_UI8 busID, PLAT_UI8 devAddr)
{
	const struct device *dev = stsephyr_platform_get(busID);

	ARG_UNUSED(devAddr);
	if (dev == NULL || stsephyr_set_reset(dev, true) != 0) {
		return STSE_PLATFORM_POWER_ERROR;
	}

	return STSE_OK;
}
