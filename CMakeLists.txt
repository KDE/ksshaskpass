cmake_minimum_required(VERSION 2.8.12)

project(ksshaskpass)
 
find_package(Qt5 REQUIRED COMPONENTS Core)

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECompilerSettings)
include(KDECMakeSettings)
include(FeatureSummary)

find_package(KF5 REQUIRED COMPONENTS
    CoreAddons
    I18n
    Wallet
    WidgetsAddons
)

set(ksshaskpass_SRCS src/main.cpp)
 
add_executable(ksshaskpass ${ksshaskpass_SRCS})
target_link_libraries(ksshaskpass 
    KF5::CoreAddons
    KF5::I18n
    KF5::Wallet
    KF5::WidgetsAddons
)

install(TARGETS ksshaskpass DESTINATION ${INSTALL_TARGETS_DEFAULT_ARGS})
install(FILES src/ksshaskpass.desktop DESTINATION ${XDG_APPS_INSTALL_DIR})

install(FILES doc/ksshaskpass.1 DESTINATION ${MAN_INSTALL_DIR}/man1)
