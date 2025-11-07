#include "config.h"
#include "vigenere_cipher.h"
#include "aes_cipher.h"
#include "modes.h"
#include <fstream>
#include <iostream>
#include <memory>

static bytes read_file(const std::string &p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open input file");
    
    f.seekg(0, std::ios::end);
    size_t n = static_cast<size_t>(f.tellg());
    f.seekg(0);
    bytes b(n);
    f.read(reinterpret_cast<char*>(b.data()), n);
    return b;
}


static void write_file(const std::string &p, const bytes &b) {
    std::ofstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open output file");
    f.write(reinterpret_cast<const char*>(b.data()), b.size());
}

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " config.json\n"; return 1;
        }
        Config cfg = load_config(argv[1]);
        std::unique_ptr<BlockCipher> bc;
        
        if (cfg.algorithm == "vigenere") bc.reset(new VigenereCipher(cfg.block_size_bits));
        else if (cfg.algorithm == "aes") bc.reset(new AesCipher());
        else throw std::runtime_error("Unknown algorithm");

        bytes input = read_file(cfg.input_file);
        bytes output;
        if (cfg.encrypt) output = encrypt_data(*bc, cfg.key, cfg.iv, input, cfg.mode, cfg.padding);
        else output = decrypt_data(*bc, cfg.key, cfg.iv, input, cfg.mode, cfg.padding);
        
        write_file(cfg.output_file, output);
        std::cout << "Operation finished. Wrote " << output.size() << " bytes to " << cfg.output_file << "\n";
        return 0;
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}