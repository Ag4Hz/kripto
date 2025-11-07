#include "aes_cipher.h"
#include <openssl/evp.h>
#include <stdexcept>

AesCipher::AesCipher(size_t bits) {
    (void)bits; // block size fixed for AES
}

void AesCipher::encrypt_block(const bytes &in, bytes &out, const bytes &key) {
    if (in.size() != 16) throw std::runtime_error("AES block size must be 16 bytes");
    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16) cipher = EVP_aes_128_ecb();
    else if (key.size() == 24) cipher = EVP_aes_192_ecb();
    else if (key.size() == 32) cipher = EVP_aes_256_ecb();
    else throw std::runtime_error("AES key must be 16/24/32 bytes");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    out.assign(16, 0);
    
    int len = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &len, in.data(), 16) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    
    int len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data()+len, &len2) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}

void AesCipher::decrypt_block(const bytes &in, bytes &out, const bytes &key) {
    if (in.size() != 16) throw std::runtime_error("AES block size must be 16 bytes");
    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16) cipher = EVP_aes_128_ecb();
    else if (key.size() == 24) cipher = EVP_aes_192_ecb();
    else if (key.size() == 32) cipher = EVP_aes_256_ecb();
    else throw std::runtime_error("AES key must be 16/24/32 bytes");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    out.assign(16, 0);
    
    int len = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &len, in.data(), 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    
    int len2 = 0;
    if (EVP_DecryptFinal_ex(ctx, out.data()+len, &len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}