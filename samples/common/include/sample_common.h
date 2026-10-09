/*
 * Copyright (c) 2026 STMicroelectronics
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STSEPHYR_SAMPLE_COMMON_H_
#define STSEPHYR_SAMPLE_COMMON_H_

#include <stddef.h>
#include <stdint.h>

#include <stsephyr/stsafe_a120.h>

/* Acquire the STSAFE-A120 for the rest of the sample. Prints the error on failure. */
int sample_open(stse_Handler_t **handler);

/* Release the device acquired with sample_open(). */
void sample_close(void);

/* Print "<operation>: OK", or a FAIL line with the STSELib status. Returns 0 on STSE_OK. */
int sample_check(const char *operation, stse_ReturnCode_t status);

void sample_print_hex(const char *label, const uint8_t *data, size_t length);

#endif /* STSEPHYR_SAMPLE_COMMON_H_ */
