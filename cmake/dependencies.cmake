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
        CACHE FILEPATH "OpenSSL crypto library"
    )

    set(OPENSSL_CRYPTO_LIBRARY
        "${OPENSSL_ROOT_DIR}/libcrypto.so"
        CACHE FILEPATH "OpenSSL crypto library"
    )
else()
    message(STATUS "Configuring system OpenSSL")
endif()

find_package(OpenSSL REQUIRED)


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