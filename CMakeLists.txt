cmake_minimum_required(VERSION 3.11)
project(radio_proxy)

set(CMAKE_CXX_STANDARD 14)

add_executable(radio-proxy radio-proxy.cpp err.h err.c)
add_executable(test-client test-client.cpp err.h err.c)
add_executable(radio-client radio-client.cpp err.c err.h)

find_package(Doxygen)
if (DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
            ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            )
endif (DOXYGEN_FOUND)