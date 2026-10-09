/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <stselib.h>

#define STSEPHYR_CRC16_INITIAL 0xFFFFU
#define STSEPHYR_CRC16_POLY    0x8408U

static uint16_t crc_state = STSEPHYR_CRC16_INITIAL;

static uint16_t crc_update(uint16_t crc, const uint8_t *data, size_t length)
{
	for (size_t i = 0; i < length; ++i) {
		crc ^= data[i];
		for (uint8_t bit = 0; bit < 8U; ++bit) {
			crc = (crc & 1U) != 0U ? (crc >> 1) ^ STSEPHYR_CRC16_POLY : crc >> 1;
		}
	}

	return crc;
}

stse_ReturnCode_t stse_platform_crc16_init(void)
{
	crc_state = STSEPHYR_CRC16_INITIAL;
	return STSE_OK;
}

PLAT_UI16 stse_platform_Crc16_Calculate(PLAT_UI8 *pbuffer, PLAT_UI16 length)
{
	if (pbuffer == NULL && length != 0U) {
		return 0U;
	}

	crc_state = crc_update(STSEPHYR_CRC16_INITIAL, pbuffer, length);
	return (uint16_t)~crc_state;
}

PLAT_UI16 stse_platform_Crc16_Accumulate(PLAT_UI8 *pbuffer, PLAT_UI16 length)
{
	if (pbuffer == NULL && length != 0U) {
		return 0U;
	}

	crc_state = crc_update(crc_state, pbuffer, length);
	return (uint16_t)~crc_state;
}
