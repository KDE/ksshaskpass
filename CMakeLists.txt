project(ksshaskpass)
cmake_minimum_required(VERSION 2.8.12)
set(PROJECT_VERSION "5.15.80")

set(QT_MIN_VERSION "5.11.0")
set(KF5_MIN_VERSION "5.58.0")

find_package(Qt5 ${QT_MIN_VERSION} REQUIRED COMPONENTS Core)

find_package(ECM ${KF5_MIN_VERSION} REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDEFrameworkCompilerSettings NO_POLICY_SCOPE)
include(KDECMakeSettings)
include(FeatureSummary)
include(ECMQtDeclareLoggingCategory)

add_definitions(-DQT_NO_NARROWING_CONVERSIONS_IN_CONNECT)

find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
    CoreAddons
    I18n
    Wallet
    WidgetsAddons
)

find_package(KF5DocTools)
set_package_properties(KF5DocTools PROPERTIES TYPE OPTIONAL
   PURPOSE "Required to build ksshaskpass manpage")

set(ksshaskpass_SRCS src/main.cpp)
 
add_executable(ksshaskpass ${ksshaskpass_SRCS})
target_compile_definitions(ksshaskpass PRIVATE -DPROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(ksshaskpass 
    KF5::CoreAddons
    KF5::I18n
    KF5::Wallet
    KF5::WidgetsAddons
)

install(TARGETS ksshaskpass DESTINATION ${INSTALL_TARGETS_DEFAULT_ARGS})

if (KF5DocTools_FOUND)
    add_subdirectory(doc)
endif()
feature_summary(WHAT ALL INCLUDE_QUIET_PACKAGES FATAL_ON_MISSING_REQUIRED_PACKAGES)
