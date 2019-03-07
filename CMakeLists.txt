cmake_minimum_required(VERSION 3.13)
project(apache-modules C)

set(CMAKE_C_STANDARD 11)

include_directories("${PROJECT_SOURCE_DIR}/src")
add_subdirectory("src")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/modules/")
