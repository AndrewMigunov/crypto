add_executable(crypto_cli main.c)
target_link_libraries(crypto_cli PRIVATE crypto_static)
crypto_set_project_warnings(crypto_cli)
set_target_properties(crypto_cli PROPERTIES OUTPUT_NAME crypto-cli)

if(CRYPTO_ENABLE_COVERAGE)
    target_compile_options(crypto_cli PRIVATE --coverage -O0 -g)
    target_link_options(crypto_cli PRIVATE --coverage)
endif()

install(TARGETS crypto_cli
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
