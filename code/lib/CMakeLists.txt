cmake_minimum_required(VERSION 3.22)

project(cpputils LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIB "Build the shared library" ON)

########################
## Main library build ##
########################

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB_RECURSE PROJECT_SRC_FILESET
    ${PROJECT_SRC_DIR}/*.cpp
)

if(BUILD_SHARED_LIB)
    add_library(${PROJECT_NAME} SHARED ${PROJECT_SRC_FILESET})
else()
    add_library(${PROJECT_NAME} STATIC ${PROJECT_SRC_FILESET})
endif()

target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_INC_DIR})

#
# Platform dependencies
#

if(ANDROID)
    message(STATUS "Building cpputils for Android")
    #message(STATUS "OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        jsoncpp_lib)
else()
    message(STATUS "Building cpputils for desktop")
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL jsoncpp_lib)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES EXPORT_NAME ${PROJECT_NAME})