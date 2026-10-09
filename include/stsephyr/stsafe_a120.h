/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STSEPHYR_STSAFE_A120_H_
#define STSEPHYR_STSAFE_A120_H_

#include <zephyr/device.h>
#include <zephyr/kernel.h>

#include <stselib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Acquire serialized access to an STSAFE-A120 STSELib handle.
 *
 * The lock covers all STSELib instances because the STSELib platform
 * callbacks for CRC and streaming crypto share state.
 *
 * @param dev STSAFE-A120 Zephyr device.
 * @param timeout Maximum time to wait for access.
 * @param handler Receives the initialized STSELib handle on success.
 * @return 0 on success or a negative errno value.
 */
int stsephyr_acquire(const struct device *dev, k_timeout_t timeout, stse_Handler_t **handler);

/** Release a handle obtained from stsephyr_acquire(). */
void stsephyr_release(const struct device *dev);

/** Reset the secure element and reinitialize its STSELib handle. */
int stsephyr_reset(const struct device *dev, k_timeout_t timeout);

/** Convert a common STSELib status to a Zephyr errno value. */
int stsephyr_stse_to_errno(stse_ReturnCode_t status);

#ifdef __cplusplus
}
#endif

#endif /* STSEPHYR_STSAFE_A120_H_ */
