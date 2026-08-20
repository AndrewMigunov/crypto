add_executable(cryptomoon_tests test_cryptomoon.c)
target_link_libraries(cryptomoon_tests PRIVATE cryptomoon_static)
target_include_directories(cryptomoon_tests SYSTEM PRIVATE third_party/acutest)
cryptomoon_set_project_warnings(cryptomoon_tests)
set_target_properties(cryptomoon_tests PROPERTIES C_EXTENSIONS OFF)

if(CRYPTOMOON_ENABLE_COVERAGE)
    target_compile_options(cryptomoon_tests PRIVATE --coverage -O0 -g)
    target_link_options(cryptomoon_tests PRIVATE --coverage)
endif()

add_test(NAME cryptomoon.unit COMMAND cryptomoon_tests)

if(NOT CRYPTOMOON_ENABLE_COVERAGE)
    add_executable(cryptomoon_tests_shared test_cryptomoon.c)
    target_link_libraries(cryptomoon_tests_shared PRIVATE cryptomoon_shared)
    target_include_directories(cryptomoon_tests_shared SYSTEM PRIVATE third_party/acutest)
    cryptomoon_set_project_warnings(cryptomoon_tests_shared)
    set_target_properties(cryptomoon_tests_shared PROPERTIES C_EXTENSIONS OFF)
    add_test(NAME cryptomoon.shared.unit COMMAND cryptomoon_tests_shared)
    if(WIN32)
        set_tests_properties(cryptomoon.shared.unit PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:$<TARGET_FILE_DIR:cryptomoon_shared>"
        )
    endif()
endif()

if(NOT CRYPTOMOON_ENABLE_COVERAGE)
    add_test(NAME cryptomoon.package
        COMMAND ${CMAKE_COMMAND}
            -DCRYPTOMOON_BINARY_DIRECTORY=${CMAKE_BINARY_DIR}
            -DCRYPTOMOON_C_COMPILER=${CMAKE_C_COMPILER}
            -DCRYPTOMOON_GENERATOR=${CMAKE_GENERATOR}
            -DCRYPTOMOON_PACKAGE_SOURCE_DIRECTORY=${CMAKE_CURRENT_SOURCE_DIR}/package
            -DCRYPTOMOON_PACKAGE_TEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/package-test
            -DCRYPTOMOON_PACKAGE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCRYPTOMOON_PACKAGE_VERSION=${PROJECT_VERSION}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_package.cmake
    )
    set_tests_properties(cryptomoon.package PROPERTIES TIMEOUT 60)
endif()

if(TARGET cryptomoon_cli)
    add_test(NAME cryptomoon.cli.help COMMAND cryptomoon_cli --help)
    set_tests_properties(cryptomoon.cli.help PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage:"
    )

    add_test(NAME cryptomoon.cli.des.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm des
            --key 133457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.des.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "85e813540f0ab405"
    )

    add_test(NAME cryptomoon.cli.des.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm des
            --key 133457799bbcdff1 --input 85e813540f0ab405
    )
    set_tests_properties(cryptomoon.cli.des.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "0123456789abcdef"
    )

    add_test(NAME cryptomoon.cli.2tdes.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm 2tdes
            --key 0123456789abcdef23456789abcdef01 --input fedcba9876543210
    )
    set_tests_properties(cryptomoon.cli.2tdes.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "b08ccaefcf225860"
    )

    add_test(NAME cryptomoon.cli.2tdes.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm 2tdes
            --key 0123456789abcdef23456789abcdef01 --input b08ccaefcf225860
    )
    set_tests_properties(cryptomoon.cli.2tdes.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "fedcba9876543210"
    )

    add_test(NAME cryptomoon.cli.3tdes.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm 3tdes
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --input fedcba9876543210
    )
    set_tests_properties(cryptomoon.cli.3tdes.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "0737f6c53750d4a4"
    )

    add_test(NAME cryptomoon.cli.3tdes.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm 3tdes
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --input 0737f6c53750d4a4
    )
    set_tests_properties(cryptomoon.cli.3tdes.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "fedcba9876543210"
    )

    add_test(NAME cryptomoon.cli.file-round-trip
        COMMAND ${CMAKE_COMMAND}
            -DCRYPTOMOON_CLI=$<TARGET_FILE:cryptomoon_cli>
            -DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/cli-file-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_cli_file.cmake
    )

    add_test(NAME cryptomoon.cli.reject-partial-block
        COMMAND cryptomoon_cli encrypt --algorithm des
            --key 133457799bbcdff1 --input 0123
    )
    set_tests_properties(cryptomoon.cli.reject-partial-block PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cryptomoon.cli.ignore-invalid-parity
        COMMAND cryptomoon_cli encrypt --algorithm des
            --key 123457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.ignore-invalid-parity PROPERTIES
        PASS_REGULAR_EXPRESSION "85e813540f0ab405"
    )
endif()
