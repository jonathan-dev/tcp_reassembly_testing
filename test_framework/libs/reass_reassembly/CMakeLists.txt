cmake_minimum_required(VERSION 3.19)
project(reass_test)

#set(REASS_INSTALL_DIR /home/jo/Desktop/reass/usr/local)

#include_directories(${REASS_INSTALL_DIR}/include/)
#link_directories(${REASS_INSTALL_DIR}/lib/)


set(CMAKE_CXX_STANDARD 14)

include(ExternalProject)

set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)

ExternalProject_Add(libreass
        GIT_REPOSITORY https://github.com/jonathan-dev/reass.git
        LOG_DOWNLOAD ON
        LOG_CONFIGURE ON
        LOG_BUILD ON
        LOG_INSTALL ON
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION} -DCMAKE_BUILD_TYPE=Release
        )

link_directories(external/lib)
include_directories(external/include)

find_package(Boost REQUIRED COMPONENTS system filesystem)

add_executable(main main.cpp)
target_link_libraries(main reass)
target_link_libraries(main ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
