cmake_minimum_required(VERSION 3.25)

project(crypto VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)
include(CMakePackageConfigHelpers)
include(cmake/modules/CompilerWarnings.cmake)

option(CRYPTO_BUILD_TESTS "Build the crypto test suite" ${BUILD_TESTING})
option(CRYPTO_BUILD_CLI "Build the crypto command-line application" ON)
option(CRYPTO_ENABLE_COVERAGE "Enable GCC coverage instrumentation" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    find_package(Doxygen REQUIRED COMPONENTS dot)
    set(DOXYGEN_PROJECT_NAME "crypto")
    set(DOXYGEN_PROJECT_NUMBER "${PROJECT_VERSION}")
    set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs")
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_GENERATE_LATEX NO)
    set(DOXYGEN_EXTRACT_STATIC YES)
    set(DOXYGEN_WARN_IF_UNDOCUMENTED YES)
    set(DOXYGEN_WARN_AS_ERROR YES)
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
    doxygen_add_docs(crypto_docs
        include
        src
        README.md
        ALL
        COMMENT "Generating crypto API documentation"
    )
endif()

add_library(crypto_objects OBJECT
    src/des.c
    src/status.c
    src/tdes.c
)
set_target_properties(crypto_objects PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(crypto_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
crypto_set_project_warnings(crypto_objects)

if(CRYPTO_ENABLE_COVERAGE)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR "Coverage is supported only with GCC")
    endif()
    target_compile_options(crypto_objects PRIVATE --coverage -O0 -g)
endif()

add_library(crypto_static STATIC $<TARGET_OBJECTS:crypto_objects>)
add_library(crypto_shared SHARED $<TARGET_OBJECTS:crypto_objects>)
add_library(crypto::static ALIAS crypto_static)
add_library(crypto::shared ALIAS crypto_shared)

foreach(target IN ITEMS crypto_static crypto_shared)
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME crypto_des
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endforeach()
set_target_properties(crypto_static PROPERTIES EXPORT_NAME static)
set_target_properties(crypto_shared PROPERTIES
    EXPORT_NAME shared
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)
if(CRYPTO_ENABLE_COVERAGE)
    target_link_options(crypto_shared PRIVATE --coverage)
endif()

if(CRYPTO_BUILD_CLI)
    add_subdirectory(apps/crypto_cli)
endif()

if(CRYPTO_BUILD_TESTS)
    add_subdirectory(tests)
endif()

install(TARGETS crypto_static crypto_shared
    EXPORT cryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT cryptoTargets
    FILE cryptoTargets.cmake
    NAMESPACE crypto::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crypto
)

configure_package_config_file(
    cmake/cryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crypto
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crypto
)
if(TARGET crypto_docs)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/html/
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/html
    )
endif()
