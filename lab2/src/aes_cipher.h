#ifndef AES_CIPHER_H
#define AES_CIPHER_H

#include "block_cipher.h"

class AesCipher : public BlockCipher {
    public:
        // AES-128/192/256 depending on key length
        AesCipher(size_t bits = 128);
        virtual size_t block_size_bits() const override { return 128; }
        virtual void encrypt_block(const bytes &in, bytes &out, const bytes &key) override;
        virtual void decrypt_block(const bytes &in, bytes &out, const bytes &key) override;
};

#endif