cmake_minimum_required(VERSION 3.5.0)
project(cpor VERSION 0.1.0)

set(CMAKE_C_FLAGS "-gdwarf-2 -g3")

add_executable(cpor cpor-app.c cpor-core.c cpor-file.c cpor-keys.c cpor-misc.c)
target_link_libraries(cpor crypto)
