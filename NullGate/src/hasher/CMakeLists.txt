cmake_minimum_required(VERSION 3.25)

project(hasher)

add_executable(hasher
    ./hasher.cpp
    ../nullgate/obfuscation.cpp
)

target_include_directories(hasher
    PRIVATE ../../include/
)

target_compile_features(hasher PRIVATE cxx_std_23)
