cmake_minimum_required(VERSION 3.5.0)
project(cpor VERSION 0.1.0)

IF(APPLE)

set(CMAKE_C_FLAGS "-gdwarf-2 -g3")

ELSEIF(UNIX)

set(CMAKE_C_FLAGS "-g3 -pthread")

ELSEIF(WIN32)

set(CMAKE_C_FLAGS "-g3")
include_directories(depends/win32/include)
include_directories("C:/Program Files/Mingw-w64/opt/include")
link_directories(depends/win32/lib)
link_directories("C:/Program Files/Mingw-w64/opt/lib")

ENDIF()

add_library(cpor cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor crypto curl)

add_executable(cpor-genaro cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor-genaro crypto curl)
