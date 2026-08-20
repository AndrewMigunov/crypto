cmake_minimum_required(VERSION 3.25)

project(cryptomoon VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)
include(CMakePackageConfigHelpers)
include(cmake/modules/CompilerWarnings.cmake)

option(CRYPTOMOON_BUILD_TESTS "Build the cryptomoon test suite" ${BUILD_TESTING})
option(CRYPTOMOON_BUILD_CLI "Build the cryptomoon command-line application" ON)
option(CRYPTOMOON_ENABLE_COVERAGE "Enable GCC coverage instrumentation" OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    find_package(Doxygen REQUIRED COMPONENTS dot)
    set(DOXYGEN_PROJECT_NAME "cryptomoon")
    set(DOXYGEN_PROJECT_NUMBER "${PROJECT_VERSION}")
    set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs")
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_GENERATE_LATEX NO)
    set(DOXYGEN_EXTRACT_STATIC YES)
    set(DOXYGEN_WARN_IF_UNDOCUMENTED YES)
    set(DOXYGEN_WARN_AS_ERROR YES)
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
    doxygen_add_docs(cryptomoon_docs
        include
        src
        README.md
        ALL
        COMMENT "Generating cryptomoon API documentation"
    )
endif()

add_library(cryptomoon_objects OBJECT
    src/des.c
    src/status.c
    src/tdes.c
)
set_target_properties(cryptomoon_objects PROPERTIES
    C_EXTENSIONS OFF
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(cryptomoon_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
cryptomoon_set_project_warnings(cryptomoon_objects)

if(CRYPTOMOON_ENABLE_COVERAGE)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR "Coverage is supported only with GCC")
    endif()
    target_compile_options(cryptomoon_objects PRIVATE --coverage -O0 -g)
endif()

add_library(cryptomoon_static STATIC $<TARGET_OBJECTS:cryptomoon_objects>)
add_library(cryptomoon_shared SHARED $<TARGET_OBJECTS:cryptomoon_objects>)
add_library(cryptomoon::static ALIAS cryptomoon_static)
add_library(cryptomoon::shared ALIAS cryptomoon_shared)

foreach(target IN ITEMS cryptomoon_static cryptomoon_shared)
    target_compile_features(${target} PUBLIC c_std_99)
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME cryptomoon
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endforeach()
set_target_properties(cryptomoon_static PROPERTIES EXPORT_NAME static)
set_target_properties(cryptomoon_shared PROPERTIES
    EXPORT_NAME shared
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)
target_compile_definitions(cryptomoon_shared INTERFACE CRYPTOMOON_USE_SHARED)
if(CRYPTOMOON_ENABLE_COVERAGE)
    target_link_options(cryptomoon_shared PRIVATE --coverage)
endif()

if(CRYPTOMOON_BUILD_CLI)
    add_subdirectory(apps/cryptomoon_cli)
endif()

if(CRYPTOMOON_BUILD_TESTS)
    add_subdirectory(tests)
endif()

install(TARGETS cryptomoon_static cryptomoon_shared
    EXPORT cryptomoonTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT cryptomoonTargets
    FILE cryptomoonTargets.cmake
    NAMESPACE cryptomoon::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptomoon
)

configure_package_config_file(
    cmake/cryptomoonConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cryptomoonConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptomoon
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/cryptomoonConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cryptomoonConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cryptomoonConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptomoon
)
if(TARGET cryptomoon_docs)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/html/
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/html
    )
endif()
