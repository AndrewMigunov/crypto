cmake_minimum_required(VERSION 3.25)
project(cryptomoon_package_consumer LANGUAGES C)

find_package(cryptomoon ${CRYPTOMOON_REQUIRED_VERSION} REQUIRED CONFIG)

foreach(linkage IN ITEMS static shared)
    add_executable(cryptomoon_package_consumer_${linkage} main.c)
    target_link_libraries(cryptomoon_package_consumer_${linkage} PRIVATE cryptomoon::${linkage})
    set_target_properties(cryptomoon_package_consumer_${linkage} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
endforeach()
