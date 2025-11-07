#ifndef VIGENERE_CIPHER_H
#define VIGENERE_CIPHER_H

#include <cstdint>
#include "block_cipher.h"

class VigenereCipher : public BlockCipher {
public:
    // block_bits must be multiple of 8
    explicit VigenereCipher(size_t block_bits = 128);

    // BlockCipher interface
    virtual size_t block_size_bits() const override;
    // in and out are block-sized (block_size_bits()/8) vectors
    virtual void encrypt_block(const bytes &in, bytes &out, const bytes &key) override;
    virtual void decrypt_block(const bytes &in, bytes &out, const bytes &key) override;

private:
    size_t block_bits_;
    size_t block_bytes_;
};

#endif