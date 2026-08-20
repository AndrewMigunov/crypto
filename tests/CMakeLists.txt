add_executable(crypto_tests test_crypto.c)
target_link_libraries(crypto_tests PRIVATE crypto_static)
target_include_directories(crypto_tests SYSTEM PRIVATE third_party/acutest)
crypto_set_project_warnings(crypto_tests)

if(CRYPTO_ENABLE_COVERAGE)
    target_compile_options(crypto_tests PRIVATE --coverage -O0 -g)
    target_link_options(crypto_tests PRIVATE --coverage)
endif()

add_test(NAME crypto.unit COMMAND crypto_tests)

if(NOT CRYPTO_ENABLE_COVERAGE)
    add_executable(crypto_tests_shared test_crypto.c)
    target_link_libraries(crypto_tests_shared PRIVATE crypto_shared)
    target_include_directories(crypto_tests_shared SYSTEM PRIVATE third_party/acutest)
    crypto_set_project_warnings(crypto_tests_shared)
    add_test(NAME crypto.shared.unit COMMAND crypto_tests_shared)
    if(WIN32)
        set_tests_properties(crypto.shared.unit PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:$<TARGET_FILE_DIR:crypto_shared>"
        )
    endif()
endif()

if(TARGET crypto_cli)
    add_test(NAME crypto.cli.help COMMAND crypto_cli --help)
    set_tests_properties(crypto.cli.help PROPERTIES
        PASS_REGULAR_EXPRESSION "Usage:"
    )

    add_test(NAME crypto.cli.des.encrypt
        COMMAND crypto_cli encrypt --algorithm des
            --key 133457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(crypto.cli.des.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "85e813540f0ab405"
    )

    add_test(NAME crypto.cli.des.decrypt
        COMMAND crypto_cli decrypt --algorithm des
            --key 133457799bbcdff1 --input 85e813540f0ab405
    )
    set_tests_properties(crypto.cli.des.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "0123456789abcdef"
    )

    add_test(NAME crypto.cli.2tdes.encrypt
        COMMAND crypto_cli encrypt --algorithm 2tdes
            --key 0123456789abcdef23456789abcdef01 --input fedcba9876543210
    )
    set_tests_properties(crypto.cli.2tdes.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "b08ccaefcf225860"
    )

    add_test(NAME crypto.cli.2tdes.decrypt
        COMMAND crypto_cli decrypt --algorithm 2tdes
            --key 0123456789abcdef23456789abcdef01 --input b08ccaefcf225860
    )
    set_tests_properties(crypto.cli.2tdes.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "fedcba9876543210"
    )

    add_test(NAME crypto.cli.3tdes.encrypt
        COMMAND crypto_cli encrypt --algorithm 3tdes
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --input fedcba9876543210
    )
    set_tests_properties(crypto.cli.3tdes.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "0737f6c53750d4a4"
    )

    add_test(NAME crypto.cli.3tdes.decrypt
        COMMAND crypto_cli decrypt --algorithm 3tdes
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --input 0737f6c53750d4a4
    )
    set_tests_properties(crypto.cli.3tdes.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "fedcba9876543210"
    )

    add_test(NAME crypto.cli.file-round-trip
        COMMAND ${CMAKE_COMMAND}
            -DCRYPTO_CLI=$<TARGET_FILE:crypto_cli>
            -DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/cli-file-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_cli_file.cmake
    )

    add_test(NAME crypto.cli.reject-partial-block
        COMMAND crypto_cli encrypt --algorithm des
            --key 133457799bbcdff1 --input 0123
    )
    set_tests_properties(crypto.cli.reject-partial-block PROPERTIES WILL_FAIL TRUE)

    add_test(NAME crypto.cli.ignore-invalid-parity
        COMMAND crypto_cli encrypt --algorithm des
            --key 123457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(crypto.cli.ignore-invalid-parity PROPERTIES
        PASS_REGULAR_EXPRESSION "85e813540f0ab405"
    )
endif()
