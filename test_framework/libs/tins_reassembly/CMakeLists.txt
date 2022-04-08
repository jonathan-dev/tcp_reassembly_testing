cmake_minimum_required(VERSION 3.19)
project(tins_test)

set(CMAKE_CXX_STANDARD 14)

include(ExternalProject)

set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)

ExternalProject_Add(libtins
        GIT_REPOSITORY https://github.com/mfontanini/libtins
        LOG_DOWNLOAD ON
        LOG_CONFIGURE ON
        LOG_BUILD ON
        LOG_INSTALL ON
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
        )

link_directories(external/lib)
include_directories(external/include)

add_executable(tins_reassembly main.cpp)
target_link_libraries(tins_reassembly tins)
