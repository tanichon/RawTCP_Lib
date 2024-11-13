cmake_minimum_required(VERSION 2.8)

project(rawtcp-lib)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -D_DEFAULT_SOURCE")

include_directories(include src)

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(LIBRARIES -lpthread)

add_executable(raw-tcpgen main.c)

add_library(rawtcp-lib STATIC
    src/segment.c src/pkt.c src/builder.c src/sck_mgr.c src/stream_builder.c)

include(GNUInstallDirs)

include_directories(lib) 

target_link_libraries(raw-tcpgen PUBLIC rawtcp-lib ${LIBRARIES})
