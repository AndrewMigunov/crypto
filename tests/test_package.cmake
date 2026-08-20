file(REMOVE_RECURSE "${CRYPTOMOON_PACKAGE_TEST_DIRECTORY}")

set(install_directory "${CRYPTOMOON_PACKAGE_TEST_DIRECTORY}/install")
set(build_directory "${CRYPTOMOON_PACKAGE_TEST_DIRECTORY}/build")

execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${CRYPTOMOON_BINARY_DIRECTORY}"
        --prefix "${install_directory}"
    RESULT_VARIABLE install_result
    ERROR_VARIABLE install_error
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "Package installation failed: ${install_error}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${CRYPTOMOON_PACKAGE_SOURCE_DIRECTORY}"
        -B "${build_directory}"
        -G "${CRYPTOMOON_GENERATOR}"
        "-DCMAKE_BUILD_TYPE=${CRYPTOMOON_PACKAGE_BUILD_TYPE}"
        "-DCMAKE_C_COMPILER=${CRYPTOMOON_C_COMPILER}"
        "-DCMAKE_PREFIX_PATH=${install_directory}"
        "-DCRYPTOMOON_REQUIRED_VERSION=${CRYPTOMOON_PACKAGE_VERSION}"
    RESULT_VARIABLE configure_result
    ERROR_VARIABLE configure_error
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "Package consumer configuration failed: ${configure_error}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${build_directory}"
    RESULT_VARIABLE build_result
    ERROR_VARIABLE build_error
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "Package consumer build failed: ${build_error}")
endif()

foreach(linkage IN ITEMS static shared)
    execute_process(
        COMMAND "${build_directory}/cryptomoon_package_consumer_${linkage}"
        RESULT_VARIABLE run_result
        ERROR_VARIABLE run_error
    )
    if(NOT run_result EQUAL 0)
        message(FATAL_ERROR "Package ${linkage} consumer failed: ${run_error}")
    endif()
endforeach()
