

cmake_minimum_required(VERSION 3.10)
project(shinject)

set(CMAKE_C_STANDARD 99)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files for the shinject library
file(GLOB SOURCES "src/*.c")

add_library(shinject STATIC ${SOURCES})

set(MAIN_SOURCE src/main.c)


add_executable(shinject_main ${MAIN_SOURCE})

target_link_libraries(shinject_main shinject)


set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)