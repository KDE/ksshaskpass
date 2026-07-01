# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Kai Uwe Broulik <kde@broulik.de>

set(testWindowPaintData_SRCS test_window_paint_data.cpp)
add_executable(prompttest tst_prompt.cpp)
target_link_libraries(prompttest PRIVATE Qt6::Core Qt6::Test ksshaskpass_prompt)
add_test(NAME prompttest COMMAND prompttest)
ecm_mark_as_test(prompttest)
