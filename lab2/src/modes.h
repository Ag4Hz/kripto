#ifndef MODES_H
#define MODES_H

#include "block_cipher.h"
#include "padding.h"
#include <functional>

enum class CipherMode { ECB, CBC, CFB, OFB, CTR };

// High-level API: encrypt/decrypt data with given block cipher implementation and key
bytes encrypt_data(BlockCipher &cipher, const bytes &key, const bytes &iv, const bytes &plaintext, CipherMode mode, PaddingMode pmod);
bytes decrypt_data(BlockCipher &cipher, const bytes &key, const bytes &iv, const bytes &ciphertext, CipherMode mode, PaddingMode pmod);

#endif