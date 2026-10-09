/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STSEPHYR_INTERNAL_H_
#define STSEPHYR_INTERNAL_H_

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>

#include <stselib.h>

#define STSEPHYR_IO_BUFFER_SIZE 756U

struct stsephyr_config {
	struct i2c_dt_spec i2c;
	struct gpio_dt_spec reset;
	uint16_t bus_speed_khz;
	uint8_t bus_id;
};

struct stsephyr_data {
	stse_Handler_t handler;
	uint8_t io_buffer[STSEPHYR_IO_BUFFER_SIZE];
	size_t frame_length;
	size_t frame_offset;
	bool ready;
};

int stsephyr_platform_register(const struct device *dev, uint8_t bus_id);
const struct device *stsephyr_platform_get(uint8_t bus_id);
int stsephyr_global_lock(k_timeout_t timeout);
void stsephyr_global_unlock(void);
int stsephyr_set_reset(const struct device *dev, bool asserted);
int stsephyr_hw_reset(const struct device *dev);

#endif /* STSEPHYR_INTERNAL_H_ */
