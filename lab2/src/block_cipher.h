#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

#include <vector>
#include <cstdint>
#include <string>

using bytes = std::vector<uint8_t>;

class BlockCipher {
    public:
        virtual ~BlockCipher() {}
        // block size in bits
        virtual size_t block_size_bits() const = 0;
        // encrypt single block (in-place) - input and output are block-size bytes
        virtual void encrypt_block(const bytes &in, bytes &out, const bytes &key) = 0;
        virtual void decrypt_block(const bytes &in, bytes &out, const bytes &key) = 0;
};

#endif