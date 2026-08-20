function(cryptomoon_set_project_warnings target)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wsign-conversion
            -Wshadow
            -Wformat=2
            -Wundef
            -Wcast-align
            -Wcast-qual
            -Wstrict-prototypes
            -Wmissing-prototypes
            -Wold-style-definition
            -Wwrite-strings
            -Wswitch-enum
            -Wdouble-promotion
            -Wnull-dereference
        )
    else()
        message(FATAL_ERROR "The project currently supports GCC only")
    endif()
endfunction()
