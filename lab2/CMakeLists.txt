cmake_minimum_required(VERSION 3.10)
project(block_cipher_framework LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
if (MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

find_package(OpenSSL REQUIRED)

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