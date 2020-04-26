cmake_minimum_required(VERSION 3.0)
project(AES128)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++11 -g")
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall")
set(CMAKE_BUILD_TYPE  DEBUG)

# option(PLATFORM "compile platform" arm) #默认arm平台
add_definitions(-DNDEBUG) #屏蔽DEBUG信息

#include_directories
include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

#link_directories
link_directories(
    ${PROJECT_SOURCE_DIR}/lib
)

set(SOURCES
	${PROJECT_SOURCE_DIR}/src/aes128.cc
)

#.so
add_library(aes128 SHARED ${SOURCES})

# target libraries
target_link_libraries(
    aes128
    
    m 
    crypto
    dl
)