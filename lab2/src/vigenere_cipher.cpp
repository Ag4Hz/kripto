#include "vigenere_cipher.h"
#include <stdexcept>

VigenereCipher::VigenereCipher(size_t block_bits)
  : block_bits_(block_bits)
{
    if (block_bits_ % 8 != 0) throw std::runtime_error("VigenereCipher: block size must be multiple of 8 bits");
    block_bytes_ = block_bits_ / 8;
}

size_t VigenereCipher::block_size_bits() const {
    return block_bits_;
}

void VigenereCipher::encrypt_block(const bytes &in, bytes &out, const bytes &key) {
    if (in.size() != block_bytes_) throw std::runtime_error("VigenereCipher::encrypt_block: input block size mismatch");
    if (key.empty()) throw std::runtime_error("VigenereCipher::encrypt_block: key must not be empty");

    out.resize(block_bytes_);
    size_t key_len = key.size();
    for (size_t i = 0; i < block_bytes_; ++i) {
        // binary Vigenere: add key byte modulo 256
        uint8_t k = key[i % key_len];
        out[i] = static_cast<uint8_t>((static_cast<uint16_t>(in[i]) + k) & 0xFF);
    }
}

void VigenereCipher::decrypt_block(const bytes &in, bytes &out, const bytes &key) {
    if (in.size() != block_bytes_) throw std::runtime_error("VigenereCipher::decrypt_block: input block size mismatch");
    if (key.empty()) throw std::runtime_error("VigenereCipher::decrypt_block: key must not be empty");

    out.resize(block_bytes_);
    size_t key_len = key.size();
    for (size_t i = 0; i < block_bytes_; ++i) {
        uint8_t k = key[i % key_len];
        // subtract key byte modulo 256
        out[i] = static_cast<uint8_t>((static_cast<int>(in[i]) - static_cast<int>(k) + 256) & 0xFF);
    }
}
