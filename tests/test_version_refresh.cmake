function(cryptomoon_run_checked error_message)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE command_result
        OUTPUT_VARIABLE command_output
        ERROR_VARIABLE command_error
    )
    if(NOT command_result EQUAL 0)
        message(FATAL_ERROR "${error_message}: ${command_output}${command_error}")
    endif()
endfunction()

file(REMOVE_RECURSE "${CRYPTOMOON_VERSION_TEST_DIRECTORY}")
set(repository_directory "${CRYPTOMOON_VERSION_TEST_DIRECTORY}/repository")
set(build_directory "${CRYPTOMOON_VERSION_TEST_DIRECTORY}/build")
file(MAKE_DIRECTORY "${repository_directory}")
file(COPY "${CRYPTOMOON_VERSION_FIXTURE}/" DESTINATION "${repository_directory}")

cryptomoon_run_checked("Git initialization failed"
    git init --quiet "${repository_directory}"
)
cryptomoon_run_checked("Initial Git add failed"
    git -C "${repository_directory}" add --all
)
cryptomoon_run_checked("Initial Git commit failed"
    git -C "${repository_directory}"
        -c user.name=cryptomoon-test
        -c user.email=cryptomoon@example.invalid
        commit --quiet -m initial
)
cryptomoon_run_checked("Version fixture configuration failed"
    "${CMAKE_COMMAND}"
        -S "${repository_directory}"
        -B "${build_directory}"
        -G "${CRYPTOMOON_GENERATOR}"
        "-DCRYPTOMOON_GIT_VERSION_MODULE=${CRYPTOMOON_GIT_VERSION_MODULE}"
)
file(READ "${build_directory}/version.txt" initial_version)
string(STRIP "${initial_version}" initial_version)

file(WRITE "${repository_directory}/revision.txt" "second revision\n")
cryptomoon_run_checked("Second Git add failed"
    git -C "${repository_directory}" add --all
)
cryptomoon_run_checked("Second Git commit failed"
    git -C "${repository_directory}"
        -c user.name=cryptomoon-test
        -c user.email=cryptomoon@example.invalid
        commit --quiet -m second
)
cryptomoon_run_checked("Version fixture rebuild failed"
    "${CMAKE_COMMAND}" --build "${build_directory}"
)
file(READ "${build_directory}/version.txt" rebuilt_version)
string(STRIP "${rebuilt_version}" rebuilt_version)

execute_process(
    COMMAND git -C "${repository_directory}" rev-parse --short=8 HEAD
    RESULT_VARIABLE git_hash_result
    OUTPUT_VARIABLE expected_version
    ERROR_VARIABLE git_hash_error
)
if(NOT git_hash_result EQUAL 0)
    message(FATAL_ERROR "Git hash lookup failed: ${git_hash_error}")
endif()
string(STRIP "${expected_version}" expected_version)

if(initial_version STREQUAL rebuilt_version)
    message(FATAL_ERROR "Version did not change after the second commit")
endif()
if(NOT rebuilt_version STREQUAL expected_version)
    message(FATAL_ERROR
        "Generated version '${rebuilt_version}' does not match Git hash '${expected_version}'"
    )
endif()
