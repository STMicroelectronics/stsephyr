# Copyright (c) 2026 STMicroelectronics
# SPDX-License-Identifier: Apache-2.0

# Helpers shared by the STSEphyr samples; include after project().
target_sources(app PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/sample_common.c)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)
