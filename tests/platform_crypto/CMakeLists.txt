# Copyright (c) 2026 STMicroelectronics
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(stsephyr_platform_crypto)

if(NOT DEFINED STSELIB_ROOT)
  set(STSELIB_ROOT "${WEST_TOPDIR}/modules/lib/stselib")
endif()

target_sources(app PRIVATE src/main.c ../../platform/stse_platform_crypto.c)
target_include_directories(app PRIVATE ../../platform ${STSELIB_ROOT})
target_compile_definitions(app PRIVATE
  CONFIG_STSEPHYR_LOG_LEVEL=3
  CONFIG_STSEPHYR_HASH_SHA256=1
  CONFIG_STSEPHYR_ECC_NIST_P256=1
  CONFIG_STSEPHYR_HOST_SESSION=1
)
