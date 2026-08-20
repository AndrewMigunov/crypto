add_executable(cryptomoon_cli main.c)
target_link_libraries(cryptomoon_cli PRIVATE cryptomoon_static)
cryptomoon_set_project_warnings(cryptomoon_cli)
set_target_properties(cryptomoon_cli PROPERTIES
    C_EXTENSIONS OFF
    OUTPUT_NAME cryptomoon-cli
)

if(CRYPTOMOON_ENABLE_COVERAGE)
    target_compile_options(cryptomoon_cli PRIVATE --coverage -O0 -g)
    target_link_options(cryptomoon_cli PRIVATE --coverage)
endif()

install(TARGETS cryptomoon_cli
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
