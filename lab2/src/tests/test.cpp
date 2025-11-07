#include "block_cipher.h"
#include "aes_cipher.h"
#include "vigenere_cipher.h"
#include "modes.h"
#include "padding.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <string>

static bool file_exists(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return !!f;
}

static std::string find_input() {
    const char* tries[] = { "cica.png", "../cica.png", "../../cica.png" };
    for (auto t : tries) if (file_exists(t)) return t;
    throw std::runtime_error("cica.png not found");
}

static bytes read_file(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + p);
    f.seekg(0, std::ios::end);
    size_t n = size_t(f.tellg());
    f.seekg(0);
    bytes b(n);
    f.read(reinterpret_cast<char*>(b.data()), n);
    return b;
}

static const char* mode_name(CipherMode m) {
    switch (m) {
        case CipherMode::ECB: return "ECB";
        case CipherMode::CBC: return "CBC";
        case CipherMode::CFB: return "CFB";
        case CipherMode::OFB: return "OFB";
        case CipherMode::CTR: return "CTR";
        default: return "?";
    }
}

static const char* pad_name(PaddingMode p) {
    switch (p) {
        case PaddingMode::SF:  return "SF";
        case PaddingMode::DES: return "DES";
        case PaddingMode::ZERO:return "ZERO";
        default: return "?";
    }
}

static void roundtrip(BlockCipher& cipher,
                      const std::string& algo,
                      const bytes& key,
                      const bytes& original,
                      CipherMode mode,
                      PaddingMode pad)
{
    size_t block_bytes = cipher.block_size_bits() / 8;
    bytes iv(block_bytes);
    for (size_t i = 0; i < iv.size(); ++i) iv[i] = static_cast<uint8_t>(i);

    bytes enc = encrypt_data(cipher, key, iv, original, mode, pad);
    bytes dec = decrypt_data(cipher, key, iv, enc, mode, pad);

    if (dec != original) {
        std::cerr << "[FAIL] " << algo << " " << mode_name(mode) << " " << pad_name(pad) << " mismatch\n";
        std::exit(1);
    }
    std::cout << "[OK] " << algo << " " << mode_name(mode) << " " << pad_name(pad) << "\n";
}

int main() {
    try {
        std::string input = find_input();
        std::cout << "Input: " << input << "\n";
        bytes original = read_file(input);

        CipherMode modes[] = { CipherMode::ECB, CipherMode::CBC, CipherMode::CFB, CipherMode::OFB, CipherMode::CTR };
        PaddingMode pads[] = { PaddingMode::SF, PaddingMode::DES, PaddingMode::ZERO };

        // AES
        AesCipher aes;
        bytes aes_key = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
        };
        for (auto m : modes)
            for (auto p : pads)
                roundtrip(aes, "AES", aes_key, original, m, p);

        // Vigenere
        size_t v_bits = 64;
        VigenereCipher vig(v_bits);
        std::string vkey_str = "MYSECRETKEY";
        bytes vkey(vkey_str.begin(), vkey_str.end());
        for (auto m : modes)
            for (auto p : pads)
                roundtrip(vig, "Vigenere", vkey, original, m, p);

        std::cout << "All tests passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
