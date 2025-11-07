#include "config.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

static CipherMode parse_mode(const std::string &s) {
    if (s == "ECB") return CipherMode::ECB;
    if (s == "CBC") return CipherMode::CBC;
    if (s == "CFB") return CipherMode::CFB;
    if (s == "OFB") return CipherMode::OFB;
    if (s == "CTR") return CipherMode::CTR;
    throw std::runtime_error("Unknown mode: " + s);
}

static PaddingMode parse_padding(const std::string &s) {
    if (s == "ZERO") return PaddingMode::ZERO;
    if (s == "DES") return PaddingMode::DES;
    if (s == "SF") return PaddingMode::SF;
    throw std::runtime_error("Unknown padding: " + s);
}

static bytes hex_to_bytes(const std::string &hex) {
    bytes out;
    auto clean = hex;
    if (clean.rfind("0x", 0) == 0) clean = clean.substr(2);
    if (clean.size() % 2) throw std::runtime_error("odd length hex");
    for (size_t i = 0; i < clean.size(); i += 2) {
        uint8_t val = static_cast<uint8_t>(std::stoi(clean.substr(i,2), nullptr, 16));
        out.push_back(val);
    }
    return out;
}


Config load_config(const std::string &path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open config file");
    
    json j; f >> j;
    Config cfg;
    
    cfg.block_size_bits = j.value("block_size_bits", 128);
    cfg.algorithm = j.value("algorithm", "simple");
    if (j.contains("key_hex")) cfg.key = hex_to_bytes(j["key_hex"].get<std::string>());
    else if (j.contains("key")) {
        std::string k = j["key"].get<std::string>();
    cfg.key.assign(k.begin(), k.end());
    } else throw std::runtime_error("Key not found in config");
    
    cfg.mode = parse_mode(j.value("mode", "ECB"));
    if (j.contains("iv_hex")) cfg.iv = hex_to_bytes(j["iv_hex"].get<std::string>());
    else if (j.contains("iv")) {
        std::string v = j["iv"].get<std::string>(); cfg.iv.assign(v.begin(), v.end());
    }
    cfg.padding = parse_padding(j.value("padding", "ZERO"));
    cfg.encrypt = j.value("encrypt", true);
    cfg.input_file = j.value("input_file", "in.bin");
    cfg.output_file = j.value("output_file", "out.bin");
    return cfg;
}