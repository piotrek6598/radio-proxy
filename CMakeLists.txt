cmake_minimum_required(VERSION 3.11)
project(radio_proxy)

set(CMAKE_CXX_STANDARD 14)

add_executable(radio-proxy radio-proxy.cpp err.h err.c)
add_executable(test-client test-client.cpp err.h err.c)
add_executable(radio-client radio-client.cpp err.c err.h)