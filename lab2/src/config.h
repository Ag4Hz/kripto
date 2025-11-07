#ifndef CONFIG_H
#define CONFIG_H

#include "padding.h"
#include "block_cipher.h"
#include "modes.h"
#include <string>
#include <vector>

struct Config {
    size_t block_size_bits;
    std::string algorithm; // "simple" or "aes"
    bytes key;
    CipherMode mode;
    bytes iv;
    PaddingMode padding;
    bool encrypt; // true = encrypt, false = decrypt
    std::string input_file;
    std::string output_file;
};

Config load_config(const std::string &path);

#endif