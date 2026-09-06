# ============================================================================
# SecureKeyRetriever - Professional CMake Build Configuration
# ============================================================================
# Copyright (c) 2026 Eren Taha Akkuş
# Licensed under the MIT License. See LICENSE file in the project root.
# ============================================================================

cmake_minimum_required(VERSION 3.15)

# ----------------------------------------------------------------------------
# Project Definition
# ----------------------------------------------------------------------------
project(SecureKeyRetriever
    VERSION 1.0.0
    DESCRIPTION "Secure Key Retriever for Chromium-based browsers (ABE decryption)"
    LANGUAGES CXX
)

# ----------------------------------------------------------------------------
# C++ Standard
# ----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ----------------------------------------------------------------------------
# Build Type (Default: Release)
# ----------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# ----------------------------------------------------------------------------
# Compiler Warnings and Flags
# ----------------------------------------------------------------------------
if(MSVC)
    # MSVC specific flags
    add_compile_options(
        /W4                      # Warning level 4
        /WX                      # Treat warnings as errors
        /MP                      # Multi-threaded compilation
        /std:c++17
        /permissive-             # Strict conformance
        /Zc:__cplusplus          # Correct __cplusplus value
    )
    
    # Release flags
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /Oy /GL /DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")
    
    # Debug flags
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /Ob0 /RTC1 /D_DEBUG")
    
    # Statically link CRT (optional - comment out if you prefer dynamic CRT)
    # set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # GCC/Clang flags (Linux/macOS)
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -O2
        -std=c++17
    )
endif()

# ----------------------------------------------------------------------------
# Windows Specific Definitions
# ----------------------------------------------------------------------------
if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_WIN32_WINNT=0x0A00      # Windows 10+
        -D_CRT_SECURE_NO_WARNINGS
        -D_SCL_SECURE_NO_WARNINGS
        -DUNICODE
        -D_UNICODE
    )
endif()

# ----------------------------------------------------------------------------
# Include Directories
# ----------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ----------------------------------------------------------------------------
# Source Files (All .cpp files)
# ----------------------------------------------------------------------------
set(SOURCES
    # Main entry point
    src/main.cpp
    
    # Core modules
    src/core/ComHandler.cpp
    src/core/RegistryScanner.cpp
    src/core/MemoryScanner.cpp
    src/core/CryptoHelper.cpp
    
    # Utility modules
    src/utils/StringUtils.cpp
    src/utils/GuidUtils.cpp
    src/utils/Logger.cpp
)

# Header files (for IDE visibility, not compiled)
set(HEADERS
    include/SecureKeyRetriever.hpp
    
    include/core/ComHandler.hpp
    include/core/RegistryScanner.hpp
    include/core/MemoryScanner.hpp
    include/core/CryptoHelper.hpp
    
    include/utils/StringUtils.hpp
    include/utils/GuidUtils.hpp
    include/utils/Logger.hpp
)

# ----------------------------------------------------------------------------
# Create Executable
# ----------------------------------------------------------------------------
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})

# ----------------------------------------------------------------------------
# Link Libraries (Windows specific)
# ----------------------------------------------------------------------------
if(WIN32)
    target_link_libraries(${PROJECT_NAME}
        bcrypt.lib          # Cryptographic API (AES-GCM)
        ole32.lib           # COM initialization
        rpcrt4.lib          # GUID manipulation
        shell32.lib         # Shell operations (SHGetFolderPath)
        user32.lib          # Window/user functions
        advapi32.lib        # Registry access
        # sqlite3.lib       # Uncomment if you link SQLite statically
    )
else()
    # Linux/macOS: typically no extra libs, but might need dl, pthread
    target_link_libraries(${PROJECT_NAME}
        pthread
        dl
    )
endif()

# ----------------------------------------------------------------------------
# Post-build: Copy executables to output directory (optional)
# ----------------------------------------------------------------------------
if(MSVC)
    # Set output directory to project root/bin
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

# ----------------------------------------------------------------------------
# Print Configuration Summary
# ----------------------------------------------------------------------------
message(STATUS "")
message(STATUS "==================================================")
message(STATUS "  SecureKeyRetriever Build Configuration")
message(STATUS "==================================================")
message(STATUS "  Project Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard:    C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:      ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:        ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Output Dir:      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "==================================================")
message(STATUS "")
