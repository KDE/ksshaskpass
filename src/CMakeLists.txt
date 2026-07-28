# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Kai Uwe Broulik <kde@broulik.de>

add_library(ksshaskpass_prompt OBJECT prompt.cpp prompt.h)

ki18n_wrap_ui(ui_SRCS cleartextinputdialog.ui)
target_sources(ksshaskpass_prompt PRIVATE ${ui_SRCS})

target_include_directories(ksshaskpass_prompt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

ecm_qt_declare_logging_category(ksshaskpass_prompt HEADER debug.h
                                               IDENTIFIER LOG_KSSHASKPASS
                                               CATEGORY_NAME ksshaskpass
                                               DESCRIPTION "ksshaskpass")

target_link_libraries(ksshaskpass_prompt PUBLIC Qt6::Core)

add_executable(ksshaskpass main.cpp)
target_compile_definitions(ksshaskpass PRIVATE -DPROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(ksshaskpass
    KF6::CoreAddons
    KF6::I18n
    KF6::WidgetsAddons
    Qt6Keychain::Qt6Keychain
    ksshaskpass_prompt
)
