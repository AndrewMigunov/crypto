function(cryptomoon_get_git_commit_short output_variable source_directory)
    set(git_commit_short "unknown")
    find_package(Git QUIET)

    if(Git_FOUND AND EXISTS "${source_directory}/.git")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --git-path HEAD
            WORKING_DIRECTORY ${source_directory}
            RESULT_VARIABLE git_head_result
            OUTPUT_VARIABLE git_head_path
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(git_head_result EQUAL 0)
            get_filename_component(git_head_path "${git_head_path}" ABSOLUTE
                                   BASE_DIR "${source_directory}")
            set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${git_head_path}")
        endif()

        execute_process(
            COMMAND ${GIT_EXECUTABLE} symbolic-ref --quiet HEAD
            WORKING_DIRECTORY ${source_directory}
            RESULT_VARIABLE git_reference_result
            OUTPUT_VARIABLE git_reference
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(git_reference_result EQUAL 0)
            execute_process(
                COMMAND ${GIT_EXECUTABLE} rev-parse --git-path ${git_reference}
                WORKING_DIRECTORY ${source_directory}
                RESULT_VARIABLE git_reference_path_result
                OUTPUT_VARIABLE git_reference_path
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
            )
            if(git_reference_path_result EQUAL 0)
                get_filename_component(git_reference_path "${git_reference_path}" ABSOLUTE
                                       BASE_DIR "${source_directory}")
                set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                             "${git_reference_path}")
            endif()
        endif()

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
