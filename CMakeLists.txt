# SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause)
#
# Copyright (c) 2020 NVIDIA CORPORATION. All rights reserved
# Run cmake as:
#  mkdir build
#  cmake ..
#  make
#  -DCMAKE_BUILD_TYPE=Debug
#      Change the optimization level, Debug disables optimization,

cmake_minimum_required(VERSION 2.8.11)
set(LIB_MAJOR_VERSION "0")
set(LIB_MINOR_VERSION "1")
set(LIB_PATCH_VERSION "5")
set(LIB_VERSION_STRING "${LIB_MAJOR_VERSION}.${LIB_MINOR_VERSION}.${LIB_PATCH_VERSION}")

if (CMAKE_VERSION VERSION_LESS 3.0)
	PROJECT(ibarr C)
	set(PROJECT_VERSION ${LIB_VERSION_STRING})
else()
	cmake_policy(SET CMP0048 NEW)
	project(ibarr
		VERSION "${LIB_VERSION_STRING}"
		LANGUAGES C)
endif()
set(CMAKE_C_COMPILER_NAMES gcc clang)
include_directories("include")
add_executable(ibarr
	src/main.c src/log.c src/msg_check.c src/ipr_client.c src/ipr_server.c src/nl_rdma.c src/path_resolve.c)
target_compile_options(ibarr PRIVATE -Wall -g)

FIND_PACKAGE(PkgConfig REQUIRED)
pkg_check_modules(NL libnl-3.0 libnl-route-3.0 REQUIRED)
include_directories(${NL_INCLUDE_DIRS})

#-------------------------
# Find libraries
# pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

#libnl-3
find_library(LibNL3_LIBRARY NAMES nl-3)
if (LibNL3_LIBRARY)
	message(STATUS "Found libnl-3-dev")
else()
	message(FATAL_ERROR "Could not find libnl-3-dev")
endif()

#libnl-route-3
find_library(LibNL3_ROUTE_LIBRARY NAMES nl-route-3)
if (LibNL3_ROUTE_LIBRARY)
	message(STATUS "Found libnl-route-3-dev")
else()
	message(FATAL_ERROR "Could not find libnl-route-3-dev")
endif()

#libibverbs
find_library(LibIBVERBS_LIBRARY NAMES ibverbs)
if (LibIBVERBS_LIBRARY)
	message(STATUS "Found libibverbs")
else()
	message(FATAL_ERROR "Could not find libibverbs")
endif()

#libibumad
find_library(LibIBUMAD_LIBRARY NAMES ibumad)
if (LibIBUMAD_LIBRARY)
	message(STATUS "Found libibumad")
else()
	message(FATAL_ERROR "Could not find libibumad")
endif()

target_link_libraries(ibarr ${CMAKE_THREAD_LIBS_INIT} ${LibNL3_LIBRARY} ${LibNL3_ROUTE_LIBRARY} ${LibIBVERBS_LIBRARY} ${LibIBUMAD_LIBRARY})
set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/buildlib/config.h.in" "${CMAKE_BINARY_DIR}/config.h")
include_directories(${PROJECT_BINARY_DIR})

install(TARGETS ibarr DESTINATION bin)

install(FILES ibarr.service DESTINATION /lib/systemd/system)
