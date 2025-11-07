#include "../src/config.h"
#include "../src/aes_cipher.h"
#include "../src/vigenere_cipher.h"
#include "../src/modes.h"
#include <iostream>
#include <cassert>
#include <random>

// Helper to generate random bytes
bytes random_bytes(size_t n) {
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 255);
    bytes b(n);
    for (auto &x : b) x = dist(rng);
    return b;
}

void test_roundtrip(BlockCipher &cipher, const bytes &key, const bytes &iv,
                    CipherMode mode, PaddingMode padding) {
    bytes data = random_bytes(1024 * 64); // 64KB
    auto enc = encrypt_data(cipher, key, iv, data, mode, padding);
    auto dec = decrypt_data(cipher, key, iv, enc, mode, padding);
    assert(data == dec && "Roundtrip failed");
}

int main() {
    try {
        AesCipher aes;
        bytes key = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                     0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        bytes iv = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
        std::cout << "Testing AES roundtrip...\n";
        test_roundtrip(aes, key, iv, CipherMode::CBC, PaddingMode::SF);
        test_roundtrip(aes, key, iv, CipherMode::CTR, PaddingMode::ZERO);

        VigenereCipher simple(64);
        bytes simple_key = {'M','Y','K','E','Y'};
        std::cout << "Testing Simple cipher roundtrip...\n";
        test_roundtrip(simple, simple_key, {}, CipherMode::ECB, PaddingMode::ZERO);

        std::cout << "✅ All tests passed successfully.\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Test failed: " << e.what() << "\n";
        return 1;
    }
}
