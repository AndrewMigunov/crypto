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

add_executable(cryptomoon_internal_tests test_tdes_internal.c)
target_link_libraries(cryptomoon_internal_tests PRIVATE cryptomoon_static)
target_include_directories(cryptomoon_internal_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(cryptomoon_internal_tests SYSTEM PRIVATE third_party/acutest)
cryptomoon_set_project_warnings(cryptomoon_internal_tests)
set_target_properties(cryptomoon_internal_tests PROPERTIES C_EXTENSIONS OFF)

if(CRYPTOMOON_ENABLE_COVERAGE)
    target_compile_options(cryptomoon_internal_tests PRIVATE --coverage -O0 -g)
    target_link_options(cryptomoon_internal_tests PRIVATE --coverage)
endif()

add_test(NAME cryptomoon.internal.unit COMMAND cryptomoon_internal_tests)

add_test(NAME cryptomoon.version-refresh
    COMMAND ${CMAKE_COMMAND}
        -DCRYPTOMOON_GENERATOR=${CMAKE_GENERATOR}
        -DCRYPTOMOON_GIT_VERSION_MODULE=${PROJECT_SOURCE_DIR}/cmake/modules/GitVersion.cmake
        -DCRYPTOMOON_VERSION_FIXTURE=${CMAKE_CURRENT_SOURCE_DIR}/version
        -DCRYPTOMOON_VERSION_TEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/version-test
        -P ${CMAKE_CURRENT_SOURCE_DIR}/test_version_refresh.cmake
)

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

    add_test(NAME cryptomoon.cli.version COMMAND cryptomoon_cli --version)
    set_tests_properties(cryptomoon.cli.version PROPERTIES
        PASS_REGULAR_EXPRESSION
            "cryptomoon-cli ${PROJECT_VERSION}\\+${CRYPTOMOON_GIT_COMMIT_SHORT}"
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

    add_test(NAME cryptomoon.cli.accept-degenerate-2tdes
        COMMAND cryptomoon_cli encrypt --algorithm 2tdes
            --key 133457799bbcdff1123556789abcdef0 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.accept-degenerate-2tdes PROPERTIES
        PASS_REGULAR_EXPRESSION "85e813540f0ab405"
    )

    add_test(NAME cryptomoon.cli.des.cbc.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm des --mode cbc
            --key 0123456789abcdef --iv 1234567890abcdef
            --input 4e6f77206973207468652074696d6520666f7220616c6c20
    )
    set_tests_properties(cryptomoon.cli.des.cbc.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"
    )

    add_test(NAME cryptomoon.cli.des.cbc.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm des --mode cbc
            --key 0123456789abcdef --iv 1234567890abcdef
            --input e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6
    )
    set_tests_properties(cryptomoon.cli.des.cbc.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "4e6f77206973207468652074696d6520666f7220616c6c20"
    )

    add_test(NAME cryptomoon.cli.3tdes.cbc.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm 3tdes --mode cbc
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --iv cafebabecafebabe
            --input fedcba9876543210fedcba9876543210fedcba9876543210
    )
    set_tests_properties(cryptomoon.cli.3tdes.cbc.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "c2ea000c1690dadf2f11210bb3c1dc2c2ca3d89a53d496f1"
    )

    add_test(NAME cryptomoon.cli.3tdes.cbc.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm 3tdes --mode cbc
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --iv cafebabecafebabe
            --input c2ea000c1690dadf2f11210bb3c1dc2c2ca3d89a53d496f1
    )
    set_tests_properties(cryptomoon.cli.3tdes.cbc.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "fedcba9876543210fedcba9876543210fedcba9876543210"
    )

    add_test(NAME cryptomoon.cli.cbc-file-round-trip
        COMMAND ${CMAKE_COMMAND}
            -DCRYPTOMOON_CLI=$<TARGET_FILE:cryptomoon_cli>
            -DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/cli-cbc-file-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_cli_cbc_file.cmake
    )

    add_test(NAME cryptomoon.cli.cbc-without-iv
        COMMAND cryptomoon_cli encrypt --algorithm des --mode cbc
            --key 133457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.cbc-without-iv PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cryptomoon.cli.cbc-invalid-iv-length
        COMMAND cryptomoon_cli encrypt --algorithm des --mode cbc
            --key 133457799bbcdff1 --iv 1234 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.cbc-invalid-iv-length PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cryptomoon.cli.des.cfb64.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm des --mode cfb64
            --key 0123456789abcdef --iv 1234567890abcdef
            --input 4e6f77206973207468652074696d6520666f7220616c6c20
    )
    set_tests_properties(cryptomoon.cli.des.cfb64.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION
            "f3096249c7f46e51a69e839b1a92f78403467133898ea622"
    )

    add_test(NAME cryptomoon.cli.des.cfb64.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm des --mode cfb64
            --key 0123456789abcdef --iv 1234567890abcdef
            --input f3096249c7f46e51a69e839b1a92f78403467133898ea622
    )
    set_tests_properties(cryptomoon.cli.des.cfb64.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "4e6f77206973207468652074696d6520666f7220616c6c20"
    )

    add_test(NAME cryptomoon.cli.3tdes.cfb64.encrypt
        COMMAND cryptomoon_cli encrypt --algorithm 3tdes --mode cfb64
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --iv cafebabecafebabe
            --input fedcba9876543210fedcba9876543210fedcba9876543210
    )
    set_tests_properties(cryptomoon.cli.3tdes.cfb64.encrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "431ed7d7f3751929b5a6f04f01f352d0ce2dcdff576e2990"
    )

    add_test(NAME cryptomoon.cli.3tdes.cfb64.decrypt
        COMMAND cryptomoon_cli decrypt --algorithm 3tdes --mode cfb64
            --key 0123456789abcdef23456789abcdef01456789abcdef0123
            --iv cafebabecafebabe
            --input 431ed7d7f3751929b5a6f04f01f352d0ce2dcdff576e2990
    )
    set_tests_properties(cryptomoon.cli.3tdes.cfb64.decrypt PROPERTIES
        PASS_REGULAR_EXPRESSION "fedcba9876543210fedcba9876543210fedcba9876543210"
    )

    add_test(NAME cryptomoon.cli.cfb64-file-round-trip
        COMMAND ${CMAKE_COMMAND}
            -DCRYPTOMOON_CLI=$<TARGET_FILE:cryptomoon_cli>
            -DTEST_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/cli-cfb64-file-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_cli_cfb64_file.cmake
    )

    add_test(NAME cryptomoon.cli.cfb64-without-iv
        COMMAND cryptomoon_cli encrypt --algorithm des --mode cfb64
            --key 133457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.cfb64-without-iv PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cryptomoon.cli.cfb64-invalid-iv-length
        COMMAND cryptomoon_cli encrypt --algorithm des --mode cfb64
            --key 133457799bbcdff1 --iv 1234 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.cfb64-invalid-iv-length PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cryptomoon.cli.unknown-mode
        COMMAND cryptomoon_cli encrypt --algorithm des --mode ctr
            --key 133457799bbcdff1 --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.unknown-mode PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cryptomoon.cli.ecb-with-iv
        COMMAND cryptomoon_cli encrypt --algorithm des --mode ecb
            --key 133457799bbcdff1 --iv 1234567890abcdef --input 0123456789abcdef
    )
    set_tests_properties(cryptomoon.cli.ecb-with-iv PROPERTIES WILL_FAIL TRUE)
endif()
