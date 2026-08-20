function(cryptomoon_get_git_commit_short output_variable source_directory)
    set(git_commit_short "unknown")
    find_package(Git QUIET)

    if(Git_FOUND AND EXISTS "${source_directory}/.git")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short=8 HEAD
            WORKING_DIRECTORY ${source_directory}
            RESULT_VARIABLE git_result
            OUTPUT_VARIABLE git_output
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(git_result EQUAL 0)
            set(git_commit_short "${git_output}")
        endif()
    endif()

    set(${output_variable} "${git_commit_short}" PARENT_SCOPE)
endfunction()
