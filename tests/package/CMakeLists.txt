cmake_minimum_required(VERSION 3.25)
project(crypto_package_consumer LANGUAGES C)

find_package(crypto 0.1 REQUIRED CONFIG)

foreach(linkage IN ITEMS static shared)
    add_executable(crypto_package_consumer_${linkage} main.c)
    target_link_libraries(crypto_package_consumer_${linkage} PRIVATE crypto::${linkage})
    set_target_properties(crypto_package_consumer_${linkage} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
endforeach()
