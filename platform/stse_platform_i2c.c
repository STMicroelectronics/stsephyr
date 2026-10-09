/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>

#include "stsephyr_internal.h"

LOG_MODULE_DECLARE(stsephyr, CONFIG_STSEPHYR_LOG_LEVEL);

static stse_ReturnCode_t i2c_error(int error)
{
	switch (error) {
	case 0:
		return STSE_OK;
	case -ETIMEDOUT:
		return STSE_PLATFORM_BUS_RECEIVE_TIMEOUT;
	case -EAGAIN:
		return STSE_PLATFORM_BUS_ARBITRATION_LOST;
	case -EIO:
	case -ENXIO:
		return STSE_PLATFORM_BUS_ACK_ERROR;
	default:
		return STSE_PLATFORM_BUS_ERR;
	}
}

static struct stsephyr_data *get_data(PLAT_UI8 bus_id)
{
	const struct device *dev = stsephyr_platform_get(bus_id);

	return dev == NULL ? NULL : dev->data;
}

static const struct stsephyr_config *get_config(PLAT_UI8 bus_id)
{
	const struct device *dev = stsephyr_platform_get(bus_id);

	return dev == NULL ? NULL : dev->config;
}

stse_ReturnCode_t stse_platform_i2c_init(PLAT_UI8 busID)
{
	const struct stsephyr_config *config = get_config(busID);

	if (config == NULL || !i2c_is_ready_dt(&config->i2c)) {
		return STSE_PLATFORM_BUS_ERR;
	}

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
					 PLAT_UI8 *pFrame, PLAT_UI16 FrameLength)
{
	const struct stsephyr_config *config = get_config(busID);

	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	if (config == NULL || (pFrame == NULL && FrameLength != 0U)) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	return i2c_error(i2c_write_dt(&config->i2c, pFrame, FrameLength));
}

stse_ReturnCode_t stse_platform_i2c_receive(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
					    PLAT_UI8 *pFrame_header, PLAT_UI8 *pFrame_payload,
					    PLAT_UI16 *pFrame_payload_Length)
{
	ARG_UNUSED(busID);
	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	ARG_UNUSED(pFrame_header);
	ARG_UNUSED(pFrame_payload);
	ARG_UNUSED(pFrame_payload_Length);
	return STSE_PLATFORM_INVALID_PARAMETER;
}

stse_ReturnCode_t stse_platform_i2c_wake(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed)
{
	const struct stsephyr_config *config = get_config(busID);

	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	if (config == NULL) {
		return STSE_PLATFORM_INVALID_PARAMETER;
	}

	return i2c_error(i2c_write_dt(&config->i2c, NULL, 0U));
}

stse_ReturnCode_t stse_platform_i2c_send_start(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
					       PLAT_UI16 FrameLength)
{
	struct stsephyr_data *data = get_data(busID);

	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	if (data == NULL || FrameLength > sizeof(data->io_buffer)) {
		return STSE_PLATFORM_BUFFER_ERR;
	}

	data->frame_length = FrameLength;
	data->frame_offset = 0U;
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
						  PLAT_UI8 *pElement, PLAT_UI16 element_size)
{
	struct stsephyr_data *data = get_data(busID);

	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	if (data == NULL || data->frame_offset + element_size > data->frame_length) {
		return STSE_PLATFORM_BUFFER_ERR;
	}

	if (element_size != 0U) {
		if (pElement == NULL) {
			memset(&data->io_buffer[data->frame_offset], 0, element_size);
		} else {
			memcpy(&data->io_buffer[data->frame_offset], pElement, element_size);
		}
		data->frame_offset += element_size;
	}

	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_stop(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
					      PLAT_UI8 *pElement, PLAT_UI16 element_size)
{
	struct stsephyr_data *data = get_data(busID);
	const struct stsephyr_config *config = get_config(busID);
	stse_ReturnCode_t status;

	status = stse_platform_i2c_send_continue(busID, devAddr, speed, pElement, element_size);
	if (status != STSE_OK) {
		return status;
	}
	if (data == NULL || config == NULL || data->frame_offset != data->frame_length) {
		return STSE_PLATFORM_BUFFER_ERR;
	}

	return i2c_error(i2c_write_dt(&config->i2c, data->io_buffer, data->frame_length));
}

stse_ReturnCode_t stse_platform_i2c_receive_start(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
						  PLAT_UI16 frame_Length)
{
	struct stsephyr_data *data = get_data(busID);
	const struct stsephyr_config *config = get_config(busID);
	int ret;

	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	if (data == NULL || config == NULL || frame_Length > sizeof(data->io_buffer)) {
		return STSE_PLATFORM_BUFFER_ERR;
	}

	ret = i2c_read_dt(&config->i2c, data->io_buffer, frame_Length);
	if (ret != 0) {
		return i2c_error(ret);
	}

	data->frame_length = frame_Length;
	data->frame_offset = 0U;
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_continue(PLAT_UI8 busID, PLAT_UI8 devAddr,
						     PLAT_UI16 speed, PLAT_UI8 *pElement,
						     PLAT_UI16 element_size)
{
	struct stsephyr_data *data = get_data(busID);

	ARG_UNUSED(devAddr);
	ARG_UNUSED(speed);
	if (data == NULL || data->frame_offset + element_size > data->frame_length) {
		return STSE_PLATFORM_BUFFER_ERR;
	}

	if (pElement != NULL && element_size != 0U) {
		memcpy(pElement, &data->io_buffer[data->frame_offset], element_size);
	}
	data->frame_offset += element_size;
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_stop(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed,
						 PLAT_UI8 *pElement, PLAT_UI16 element_size)
{
	struct stsephyr_data *data = get_data(busID);
	stse_ReturnCode_t status;

	status = stse_platform_i2c_receive_continue(busID, devAddr, speed, pElement, element_size);
	if (status != STSE_OK) {
		return status;
	}
	if (data == NULL || data->frame_offset != data->frame_length) {
		return STSE_PLATFORM_BUFFER_ERR;
	}

	return STSE_OK;
}
