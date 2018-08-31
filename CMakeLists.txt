cmake_minimum_required(VERSION 3.5.0)
project(cpor VERSION 0.1.0)

IF(APPLE)

set(CMAKE_C_FLAGS "-gdwarf-2 -g3")

add_library(cpor cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)

add_executable(cpor-genaro cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor-genaro crypto curl)

ELSEIF(UNIX)

set(CMAKE_C_FLAGS "-g3 -pthread")

add_library(cpor cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)

add_executable(cpor-genaro cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor-genaro crypto curl)

ELSEIF(WIN32)

set(CMAKE_C_FLAGS "-DCURL_STATICLIB -Wall -std=c99 -g3")
include_directories("C:/Program Files/Mingw-w64/opt/include")
include_directories(depends/win32/include)
link_directories("C:/Program Files/Mingw-w64/opt/lib")
link_directories(depends/win32/lib)

add_library(cpor cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)

add_executable(cpor-genaro cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor-genaro crypto curl gnutls nettle hogweed gmp crypt32.a ws2_32.lib)
# target_link_libraries(cpor-genaro crypto curl gnutls nettle hogweed gmp Crypt32.lib ws2_32.lib)

ENDIF()
