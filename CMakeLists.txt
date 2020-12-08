cmake_minimum_required(VERSION 3.10.0)
project(TLSCache)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake/;${CMAKE_MODULE_PATH}")
set(LIBRESSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/extern/libressl_install")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
find_package(LibreSSL REQUIRED)

add_subdirectory(src/)
add_subdirectory(solution/)
