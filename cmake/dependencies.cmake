#
# OpenSSL
#
if(ANDROID)
    message(STATUS "Configuring Android OpenSSL")

    set(OPENSSL_ROOT_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/dep/android/openssl/${ANDROID_ABI}"
        CACHE PATH "OpenSSL root directory"
    )

    set(OPENSSL_INCLUDE_DIR
        "${OPENSSL_ROOT_DIR}/include"
        CACHE PATH "OpenSSL include directory"
    )

    set(OPENSSL_SSL_LIBRARY
        "${OPENSSL_ROOT_DIR}/libssl.so"
        CACHE FILEPATH "OpenSSL ssl library"
    )

    set(OPENSSL_CRYPTO_LIBRARY
        "${OPENSSL_ROOT_DIR}/libcrypto.so"
        CACHE FILEPATH "OpenSSL crypto library"
    )
else()
    message(STATUS "Configuring system OpenSSL")
endif()

find_package(OpenSSL REQUIRED)



get_property(allTargets GLOBAL PROPERTY TARGETS)
message(STATUS "Targets:")
foreach(t ${allTargets})
    if(t MATCHES "OpenSSL")
        message(STATUS "  ${t}")
    endif()
endforeach()



message(STATUS "OpenSSL_FOUND=${OpenSSL_FOUND}")

message(STATUS "CMake version: ${CMAKE_VERSION}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")




#if(TARGET OpenSSL::Crypto)
#    message(STATUS "Found OpenSSL::Crypto")
#else()
#    message(FATAL_ERROR "No OpenSSL::Crypto target")
#endif()


#
# jsoncpp
#

if(ANDROID)
    # Android cannot use /usr/include/jsoncpp
    message(STATUS "Configuring jsoncpp for Android")
    set(JSONCPP_WITH_TESTS OFF CACHE BOOL "" FORCE)
    set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
    set(JSONCPP_WITH_EXAMPLE OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

    add_subdirectory(
        ${REPO_DEP_ROOT_DIR}/linux/jsoncpp
        ${CMAKE_BINARY_DIR}/jsoncpp
    )
else()
    message(STATUS "Configuring jsoncpp from system")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(JSONCPP REQUIRED jsoncpp)
endif()