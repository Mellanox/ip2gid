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
set(LIB_MINOR_VERSION "0")
set(LIB_PATCH_VERSION "1")
set(LIB_VERSION_STRING "${LIB_MAJOR_VERSION}.${LIB_MINOR_VERSION}.${LIB_PATCH_VERSION}")

if (CMAKE_VERSION VERSION_LESS 3.0)
	PROJECT(ip2gid C)
	set(PROJECT_VERSION ${LIB_VERSION_STRING})
else()
	cmake_policy(SET CMP0048 NEW)
	project(ip2gid
		VERSION "${LIB_VERSION_STRING}"
		DESCRIPTION "IP 2 GID resolution over UDP"
		LANGUAGES C)
endif()
set(CMAKE_C_COMPILER_NAMES gcc clang)
include_directories("include")
add_executable(ip2gid
	src/main.c)
target_compile_options(ip2gid PRIVATE -Wall)

set(SEARCHPATHS
	/opt/local
	/sw
	/usr
	/usr/local)

find_path(NL_INCLUDE_DIRS
	PATH_SUFFIXES
		include/libnl3
		include
	NAMES
		netlink/netlink.h
	PATHS
		$(SEARCHPATHS))

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
target_link_libraries(ip2gid ${CMAKE_THREAD_LIBS_INIT} ${LibNL3_LIBRARY} ${LibNL3_ROUTE_LIBRARY})
include_directories(${NL_INCLUDE_DIRS})
set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/buildlib/config.h.in" "${CMAKE_BINARY_DIR}/config.h")
include_directories(${PROJECT_BINARY_DIR})
