cmake_minimum_required(VERSION 3.5.0)
project(cpor VERSION 0.1.0)

IF(APPLE)
set(CMAKE_C_FLAGS "-gdwarf-2 -g3")
ELSEIF(UNIX)
set(CMAKE_C_FLAGS "-g3 -pthread")
ELSEIF()
set(CMAKE_C_FLAGS "-g3")
ENDIF()

add_executable(cpor-genaro cpor-genaro.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor-genaro crypto curl)
