#ifndef PADDING_H
#define PADDING_H

#include "block_cipher.h"
#include <cstddef>
#include <cstdint>

enum class PaddingMode { ZERO, DES, SF }; // SF = Schneier-Ferguson (PKCS#7 style: n bytes of value n)

bytes apply_padding(const bytes &plain, size_t block_bytes, PaddingMode pm);
bytes remove_padding(const bytes &padded, size_t block_bytes, PaddingMode pm);

#endif