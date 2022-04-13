
project(fstream_enc)
cmake_minimum_required(VERSION 3.5)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(THIRD_PARTY_PATH  "${CMAKE_BINARY_DIR}/third_party")

set(CMAKE_CXX_STANDARD 11)
include(${CMAKE_SOURCE_DIR}/cmake/external/cryptopp.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/external/gtest.cmake)
include_directories(${CMAKE_SOURCE_DIR}/src/)

add_executable(fstream_ext_test ${CMAKE_SOURCE_DIR}/src/fstream_ext_test.cc)
target_link_libraries(fstream_ext_test gtest cryptopp)


