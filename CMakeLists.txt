project(ksshaskpass)
 
find_package(KDE4 REQUIRED)
include(KDE4Defaults)

add_definitions(${QT_DEFINITIONS} ${KDE4_DEFINITIONS})
include_directories(${KDE4_INCLUDES})
set(CMAKE_SKIP_RPATH TRUE)
 
set(ksshaskpass_SRCS src/main.cpp)
 
kde4_add_executable(ksshaskpass ${ksshaskpass_SRCS})
target_link_libraries(ksshaskpass ${KDE4_KDEUI_LIBS})

install(TARGETS ksshaskpass DESTINATION ${BIN_INSTALL_DIR})
install(FILES src/ksshaskpass.desktop DESTINATION ${XDG_APPS_INSTALL_DIR})

install(FILES doc/ksshaskpass.1 DESTINATION ${MAN_INSTALL_DIR}/man1)
