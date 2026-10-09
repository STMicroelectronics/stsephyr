# Copyright (c) 2026 STMicroelectronics
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(stsephyr_platform_crc)

if(NOT DEFINED STSELIB_ROOT)
  set(STSELIB_ROOT "${WEST_TOPDIR}/modules/lib/stselib")
endif()

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_LIST_DIR}/../../platform/stse_platform_crc.c
)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../platform
  ${STSELIB_ROOT}
)
