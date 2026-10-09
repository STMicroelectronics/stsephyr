/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STSEPHYR_PLATFORM_GENERIC_H_
#define STSEPHYR_PLATFORM_GENERIC_H_

#include <stdint.h>
#include <zephyr/toolchain.h>

#define PLAT_UI8  uint8_t
#define PLAT_UI16 uint16_t
#define PLAT_UI32 uint32_t
#define PLAT_UI64 uint64_t
#define PLAT_I8	  int8_t
#define PLAT_I16  int16_t
#define PLAT_I32  int32_t

#define PLAT_PACKED_STRUCT __packed

/* STSELib uses the CMSIS-style spelling for weak platform defaults. */
#ifndef __WEAK
#define __WEAK __weak
#endif

#ifdef CONFIG_STSEPHYR_USE_RSP_POLLING
#define STSE_USE_RSP_POLLING
#define STSE_MAX_POLLING_RETRY	    CONFIG_STSEPHYR_MAX_POLLING_RETRY
#define STSE_FIRST_POLLING_INTERVAL CONFIG_STSEPHYR_FIRST_POLLING_INTERVAL_MS
#define STSE_POLLING_RETRY_INTERVAL CONFIG_STSEPHYR_POLLING_RETRY_INTERVAL_MS
#endif

#endif /* STSEPHYR_PLATFORM_GENERIC_H_ */
