/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 *
 * CRC-16/X-25 platform callback, check value from the CRC catalogue.
 */

#include <zephyr/ztest.h>

#include <stselib.h>

ZTEST(stsephyr_crc, test_known_x25_vector)
{
	uint8_t input[] = "123456789";

	zassert_equal(stse_platform_crc16_init(), STSE_OK);
	zassert_equal(stse_platform_Crc16_Calculate(input, sizeof(input) - 1U), 0x906EU);
}

ZTEST(stsephyr_crc, test_incremental_vector)
{
	uint8_t first[] = "1234";
	uint8_t second[] = "56789";

	zassert_equal(stse_platform_crc16_init(), STSE_OK);
	(void)stse_platform_Crc16_Calculate(first, sizeof(first) - 1U);
	zassert_equal(stse_platform_Crc16_Accumulate(second, sizeof(second) - 1U), 0x906EU);
}

ZTEST_SUITE(stsephyr_crc, NULL, NULL, NULL, NULL, NULL);
