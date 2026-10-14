cmake_minimum_required (VERSION 3.22)

project("cpputils")
set(CMAKE_CXX_STANDARD 17)

option(BUILD_SHARED_LIB "Build the shared library" ON)
option(SSL_LIB_PATH "Path to SSL library" "")
option(CRYPTO_LIB_PATH "Path to crypto library" "")

########################
## Main library build ##
########################
set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_SRC_DIR}/**/*.cpp
    ${PROJECT_SRC_DIR}/*.cpp)

if(UNIX)
    set(LIBS_LINK -lssl -lcrypto -luuid -lstdc++fs -lzip)
endif(UNIX)

if(WIN32)
    set(LIBS_LINK -L${SSL_LIB_PATH} -L${CRYPTO_LIB_PATH})
endif(WIN32)

if(BUILD_SHARED_LIB)
    add_library(${PROJECT_NAME} SHARED ${PROJECT_SRC_FILESET})
else()
    add_library(${PROJECT_NAME} ${PROJECT_SRC_FILESET})
endif(BUILD_SHARED_LIB)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INC_DIR} /usr/include/jsoncpp)
target_link_libraries(${PROJECT_NAME} PUBLIC -ljsoncpp ${LIBS_LINK})
set_target_properties(${PROJECT_NAME} PROPERTIES EXPORT_NAME ${PROJECT_NAME})

