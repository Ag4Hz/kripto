cmake_minimum_required(VERSION 3.10)
project(block_cipher_framework LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
if (MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

find_package(OpenSSL REQUIRED)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -c "import pybind11; print(pybind11.get_cmake_dir())"
    OUTPUT_VARIABLE pybind11_DIR_RAW
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE pybind11_FOUND_RESULT
)

if(pybind11_FOUND_RESULT EQUAL 0)
    file(TO_CMAKE_PATH "${pybind11_DIR_RAW}" pybind11_DIR)
    message(STATUS "Found pybind11 at: ${pybind11_DIR}")
    find_package(pybind11 CONFIG REQUIRED PATHS "${pybind11_DIR}")
else()
    message(FATAL_ERROR "pybind11 not found. Install with: pip install pybind11")
endif()

add_executable(cipher_main
src/main.cpp
src/block_cipher.h
src/block_cipher.cpp
src/modes.h
src/modes.cpp
src/padding.h
src/padding.cpp
src/aes_cipher.h
src/aes_cipher.cpp
src/vigenere_cipher.h
src/vigenere_cipher.cpp
src/config.h
src/config.cpp
)

target_include_directories(cipher_main PRIVATE src)
target_link_libraries(cipher_main PRIVATE OpenSSL::Crypto)

# Tests
enable_testing()

add_executable(tests
src/tests/test.cpp
src/block_cipher.h
src/block_cipher.cpp
src/modes.h
src/modes.cpp
src/padding.h
src/padding.cpp
src/aes_cipher.h
src/aes_cipher.cpp
src/vigenere_cipher.h
src/vigenere_cipher.cpp
src/config.h
src/config.cpp
)

target_include_directories(tests PRIVATE src)
target_link_libraries(tests PRIVATE OpenSSL::Crypto)
add_test(NAME unit_tests COMMAND tests)

# Python bindings module
pybind11_add_module(crypto_module
    src/crypto_bindings.cpp
    src/modes.cpp
    src/padding.cpp
    src/block_cipher.cpp
    src/aes_cipher.cpp
)

target_include_directories(crypto_module PRIVATE src)
target_link_libraries(crypto_module PRIVATE OpenSSL::Crypto)