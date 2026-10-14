cmake_minimum_required (VERSION 3.22)

project("libcpputils-unittests")
set(CMAKE_CXX_STANDARD 17)

option(EXCLUDE_DH_TESTS "Exclude Diffie-Hellman tests in build" ON)
#option(EXCLUDE_CERT_TESTS "Exclude certificate builder tests in build" ON)
option(EXCLUDE_BCHAIN_TESTS "Exclude blockchain tests in build" OFF)

################
## Main build ##
################

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(EXCLUDE_BCHAIN_TESTS)
    add_compile_definitions(EXCLUDE_BCHAIN_TESTS)
endif(EXCLUDE_BCHAIN_TESTS)

if(EXCLUDE_DH_TESTS)
    add_compile_definitions(EXCLUDE_DH_TESTS)
endif(EXCLUDE_DH_TESTS)

#if(EXCLUDE_CERT_TESTS)
#    add_compile_definitions(EXCLUDE_CERT_TESTS)
#endif(EXCLUDE_CERT_TESTS)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_SRC_DIR}/*.cpp
    ${PROJECT_SRC_DIR}/tests/*.cpp)

#message(${PROJECT_SRC_FILESET})
add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INC_DIR} ${PROJECT_LIB_ROOT_DIR}/include)
target_link_libraries(${PROJECT_NAME} PUBLIC cpputils -ljsoncpp -lzip)

########################
## Post build tasks ##
########################

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/data ${CMAKE_CURRENT_BINARY_DIR}/data)