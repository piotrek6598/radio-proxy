cmake_minimum_required(VERSION 3.16)
project(radio_proxy)

set(CMAKE_CXX_STANDARD 14)

add_executable(radio_proxy main.cpp err.h err.c)