/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT st_stsafe_a120

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <stsephyr/stsafe_a120.h>

#include "stsephyr_internal.h"

LOG_MODULE_REGISTER(stsephyr, CONFIG_STSEPHYR_LOG_LEVEL);

BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(st_stsafe_a120) <= CONFIG_STSEPHYR_MAX_INSTANCES,
	     "Increase CONFIG_STSEPHYR_MAX_INSTANCES");

static int initialize_handler(const struct device *dev, bool reset_hardware)
{
	const struct stsephyr_config *config = dev->config;
	struct stsephyr_data *data = dev->data;
	stse_ReturnCode_t status;
	int ret;

	data->ready = false;
	if (reset_hardware) {
		ret = stsephyr_hw_reset(dev);
		if (ret != 0) {
			LOG_ERR("%s: reset failed (%d)", dev->name, ret);
			return ret;
		}
	}

	status = stse_set_default_handler_value(&data->handler);
	if (status != STSE_OK) {
		LOG_ERR("%s: default STSELib handler failed (0x%x)", dev->name, status);
		return stsephyr_stse_to_errno(status);
	}

	data->handler.device_type = STSAFE_A120;
	data->handler.io.busID = config->bus_id;
	data->handler.io.Devaddr = config->i2c.addr;
	data->handler.io.BusSpeed = config->bus_speed_khz;
	data->handler.io.BusType = STSE_BUS_TYPE_I2C;

	status = stse_init(&data->handler);
	if (status != STSE_OK) {
		LOG_ERR("%s: STSELib initialization failed (0x%x)", dev->name, status);
		return stsephyr_stse_to_errno(status);
	}

	if (data->handler.device_type != STSAFE_A120) {
		LOG_ERR("%s: attached secure element is not an STSAFE-A120", dev->name);
		return -ENODEV;
	}

	data->ready = true;
	LOG_INF("%s ready at 0x%02x on %s", dev->name, config->i2c.addr, config->i2c.bus->name);
	return 0;
}

static int stsephyr_init(const struct device *dev)
{
	const struct stsephyr_config *config = dev->config;
	int ret;

	if (!i2c_is_ready_dt(&config->i2c)) {
		LOG_ERR("%s: I2C controller is not ready", dev->name);
		return -ENODEV;
	}
	if (!gpio_is_ready_dt(&config->reset)) {
		LOG_ERR("%s: reset GPIO controller is not ready", dev->name);
		return -ENODEV;
	}

	ret = gpio_pin_configure_dt(&config->reset, GPIO_OUTPUT_INACTIVE);
	if (ret != 0) {
		LOG_ERR("%s: reset GPIO configuration failed (%d)", dev->name, ret);
		return ret;
	}

	ret = stsephyr_platform_register(dev, config->bus_id);
	if (ret != 0) {
		LOG_ERR("%s: platform context registration failed (%d)", dev->name, ret);
		return ret;
	}

	return initialize_handler(dev, true);
}

int stsephyr_acquire(const struct device *dev, k_timeout_t timeout, stse_Handler_t **handler)
{
	struct stsephyr_data *data;
	int ret;

	if (dev == NULL || handler == NULL || !device_is_ready(dev)) {
		return -ENODEV;
	}

	data = dev->data;
	ret = stsephyr_global_lock(timeout);
	if (ret != 0) {
		return ret;
	}

	if (!data->ready) {
		stsephyr_global_unlock();
		return -EIO;
	}

	*handler = &data->handler;
	return 0;
}

void stsephyr_release(const struct device *dev)
{
	if (dev == NULL) {
		return;
	}

	stsephyr_global_unlock();
}

int stsephyr_reset(const struct device *dev, k_timeout_t timeout)
{
	int ret;

	if (dev == NULL || !device_is_ready(dev)) {
		return -ENODEV;
	}
	/* A failed runtime reset must be recoverable even when data->ready is false. */
	ret = stsephyr_global_lock(timeout);
	if (ret != 0) {
		return ret;
	}
	ret = initialize_handler(dev, true);
	stsephyr_release(dev);
	return ret;
}

int stsephyr_stse_to_errno(stse_ReturnCode_t status)
{
	switch (status) {
	case STSE_OK:
		return 0;
	case STSE_PLATFORM_INVALID_PARAMETER:
	case STSE_CORE_INVALID_PARAMETER:
	case STSE_SERVICE_INVALID_PARAMETER:
	case STSE_API_INVALID_PARAMETER:
		return -EINVAL;
	case STSE_PLATFORM_BUFFER_ERR:
	case STSE_BUFFER_LENGTH_EXCEEDED:
		return -EMSGSIZE;
	case STSE_PLATFORM_BUS_RECEIVE_TIMEOUT:
		return -ETIMEDOUT;
	case STSE_ACCESS_CONDITION_NOT_SATISFIED:
	case STSE_COMMAND_NOT_AUTHORIZED:
		return -EACCES;
	case STSE_KEY_NOT_FOUND:
	case STSE_ENTRY_NOT_FOUND:
		return -ENOENT;
	default:
		return -EIO;
	}
}

#define STSEPHYR_DEFINE(inst)                                                                      \
	static struct stsephyr_data stsephyr_data_##inst;                                          \
	static const struct stsephyr_config stsephyr_config_##inst = {                             \
		.i2c = I2C_DT_SPEC_INST_GET(inst),                                                 \
		.reset = GPIO_DT_SPEC_INST_GET(inst, reset_gpios),                                 \
		.bus_speed_khz = DT_PROP(DT_BUS(DT_DRV_INST(inst)), clock_frequency) / 1000U,      \
		.bus_id = inst,                                                                    \
	};                                                                                         \
	DEVICE_DT_INST_DEFINE(inst, stsephyr_init, NULL, &stsephyr_data_##inst,                    \
			      &stsephyr_config_##inst, POST_KERNEL, CONFIG_STSEPHYR_INIT_PRIORITY, \
			      NULL);

DT_INST_FOREACH_STATUS_OKAY (STSEPHYR_DEFINE)
