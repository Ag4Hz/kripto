#include "modes.h"
#include <stdexcept>
#include <cstring>
#include <iostream>


static bytes xor_bytes(const bytes &a, const bytes &b) {
    size_t n = a.size();
    bytes out(n);
    for (size_t i = 0; i < n; ++i) {
        out[i] = a[i] ^ b[i];
    }
    return out;
}


bytes encrypt_data(BlockCipher &cipher, const bytes &key, const bytes &iv, const bytes &plaintext, CipherMode mode, PaddingMode pmod) {
    size_t block_bits = cipher.block_size_bits();
    size_t block_bytes = block_bits / 8;
    bytes pt = apply_padding(plaintext, block_bytes, pmod);
    bytes out;
    out.reserve(pt.size());

    bytes feedback(block_bytes, 0);
    if (mode != CipherMode::ECB) {
        if (iv.size() != block_bytes) throw std::runtime_error("IV must be block-sized (in bytes)");
        feedback = iv;
    }

    bytes block_in(block_bytes), block_out(block_bytes);
    for (size_t off = 0; off < pt.size(); off += block_bytes) {
        std::copy(pt.begin()+off, pt.begin()+off+block_bytes, block_in.begin());
        if (mode == CipherMode::ECB) {
            cipher.encrypt_block(block_in, block_out, key);
        } else if (mode == CipherMode::CBC) {
            bytes x = xor_bytes(block_in, feedback);
            cipher.encrypt_block(x, block_out, key);
            feedback = block_out;
        } else if (mode == CipherMode::CFB) {
            // CFB: encrypt feedback, XOR with plaintext -> ciphertext; feedback = ciphertext
            bytes s;
            cipher.encrypt_block(feedback, s, key);
            block_out = xor_bytes(block_in, s);
            feedback = block_out;
        } else if (mode == CipherMode::OFB) {
            // OFB: feedback = encrypt(feedback); ciphertext = plaintext XOR feedback
            bytes s;
            cipher.encrypt_block(feedback, s, key);
            feedback = s;
            block_out = xor_bytes(block_in, s);
        } else if (mode == CipherMode::CTR) {
            // treat feedback as counter; encrypt it to produce keystream
            bytes s;
            cipher.encrypt_block(feedback, s, key);
            block_out = xor_bytes(block_in, s);
            // increment counter (big endian)
            for (int i = static_cast<int>(block_bytes)-1; i >= 0; --i) {
                if (++feedback[i] != 0) break;
            }
        }
        out.insert(out.end(), block_out.begin(), block_out.end());
    }
    return out;
}

bytes decrypt_data(BlockCipher &cipher, const bytes &key, const bytes &iv, const bytes &ciphertext,
    CipherMode mode, PaddingMode pmod) {
    size_t block_bits = cipher.block_size_bits();
    size_t block_bytes = block_bits / 8;
    if (ciphertext.size() % block_bytes != 0) throw std::runtime_error("Ciphertext length must be multiple of block size");
    bytes out;
    out.reserve(ciphertext.size());

    bytes feedback(block_bytes, 0);
    if (mode != CipherMode::ECB) {
        if (iv.size() != block_bytes) throw std::runtime_error("IV must be block-sized (in bytes)");
        feedback = iv;
    }

    bytes block_in(block_bytes), block_out(block_bytes);
    for (size_t off = 0; off < ciphertext.size(); off += block_bytes) {
        std::copy(ciphertext.begin()+off, ciphertext.begin()+off+block_bytes, block_in.begin());
        if (mode == CipherMode::ECB) {
            cipher.decrypt_block(block_in, block_out, key);
        } else if (mode == CipherMode::CBC) {
            // decrypt then xor with feedback (previous ciphertext or IV)
            bytes dec;
            cipher.decrypt_block(block_in, dec, key);
            block_out = xor_bytes(dec, feedback);
            feedback = block_in;
        } else if (mode == CipherMode::CFB) {
            bytes s;
            cipher.encrypt_block(feedback, s, key);
            block_out = xor_bytes(block_in, s);
            feedback = block_in;
        } else if (mode == CipherMode::OFB) {
            bytes s;
            cipher.encrypt_block(feedback, s, key);
            feedback = s;
            block_out = xor_bytes(block_in, s);
        } else if (mode == CipherMode::CTR) {
            bytes s;
            cipher.encrypt_block(feedback, s, key);
            block_out = xor_bytes(block_in, s);
            for (int i = static_cast<int>(block_bytes)-1; i >= 0; --i) {
                if (++feedback[i] != 0) break;
            }
        }
        out.insert(out.end(), block_out.begin(), block_out.end());
    }
    
    return remove_padding(out, block_bytes, pmod);
}