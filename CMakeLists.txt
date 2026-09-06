cmake_minimum_required(VERSION 3.15)

project(SecureKeyRetriever
    VERSION 1.0.0
    DESCRIPTION "Secure Key Retriever for Chromium-based browsers"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Compiler Ayarları
if(MSVC)
    add_compile_options(/W4 /MP /std:c++17 /permissive- /Zc:__cplusplus /EHsc)
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /Oy /GL /DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -O2 -std=c++17)
endif()

# Windows Tanımlamaları
if(WIN32 OR MINGW)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_WIN32_WINNT=0x0A00
        -D_CRT_SECURE_NO_WARNINGS
        -DUNICODE
        -D_UNICODE
    )
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SOURCES
    src/main.cpp
    src/core/ComHandler.cpp
    src/core/RegistryScanner.cpp
    src/core/MemoryScanner.cpp
    src/core/CryptoHelper.cpp
    src/utils/StringUtils.cpp
    src/utils/GuidUtils.cpp
    src/utils/Logger.cpp
)

# Executable Oluşturma (WIN32 bayrağı kaldırıldı - konsol çıktısı ve çapraz derleme desteği için)
add_executable(${PROJECT_NAME} ${SOURCES})

# Platform/Kütüphane Bağlantıları (Uzantısız, MinGW ve MSVC Uyumlu)
if(WIN32 OR MINGW)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        bcrypt
        ole32
        oleaut32
        rpcrt4
        shell32
        user32
        advapi32
        ws2_32
    )
    if(MINGW)
        target_link_options(${PROJECT_NAME} PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
else()
    # Linux Native Derlemesi için
    target_link_libraries(${PROJECT_NAME} PRIVATE
        pthread
        dl
    )
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
