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
