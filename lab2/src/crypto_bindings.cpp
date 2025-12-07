#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "modes.h"
#include "aes_cipher.h"
#include "padding.h"

namespace py = pybind11;

// Wrapper functions for easier Python usage
std::vector<uint8_t> py_encrypt_data(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &plaintext,
    const std::string &mode_str,
    const std::string &padding_str
) {
    // Create AES cipher instance
    AesCipher cipher(128);
    
    // Parse mode
    CipherMode mode;
    if (mode_str == "ECB") mode = CipherMode::ECB;
    else if (mode_str == "CBC") mode = CipherMode::CBC;
    else if (mode_str == "CFB") mode = CipherMode::CFB;
    else if (mode_str == "OFB") mode = CipherMode::OFB;
    else if (mode_str == "CTR") mode = CipherMode::CTR;
    else throw std::runtime_error("Invalid mode: " + mode_str);
    
    // Parse padding
    PaddingMode pmod;
    if (padding_str == "ZERO") pmod = PaddingMode::ZERO;
    else if (padding_str == "DES") pmod = PaddingMode::DES;
    else if (padding_str == "SF" || padding_str == "PKCS7") pmod = PaddingMode::SF;
    else throw std::runtime_error("Invalid padding: " + padding_str);
    
    return encrypt_data(cipher, key, iv, plaintext, mode, pmod);
}

std::vector<uint8_t> py_decrypt_data(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext,
    const std::string &mode_str,
    const std::string &padding_str
) {
    // Create AES cipher instance
    AesCipher cipher(128);
    
    // Parse mode
    CipherMode mode;
    if (mode_str == "ECB") mode = CipherMode::ECB;
    else if (mode_str == "CBC") mode = CipherMode::CBC;
    else if (mode_str == "CFB") mode = CipherMode::CFB;
    else if (mode_str == "OFB") mode = CipherMode::OFB;
    else if (mode_str == "CTR") mode = CipherMode::CTR;
    else throw std::runtime_error("Invalid mode: " + mode_str);
    
    // Parse padding
    PaddingMode pmod;
    if (padding_str == "ZERO") pmod = PaddingMode::ZERO;
    else if (padding_str == "DES") pmod = PaddingMode::DES;
    else if (padding_str == "SF" || padding_str == "PKCS7") pmod = PaddingMode::SF;
    else throw std::runtime_error("Invalid padding: " + padding_str);
    
    return decrypt_data(cipher, key, iv, ciphertext, mode, pmod);
}

PYBIND11_MODULE(crypto_module, m) {
    m.doc() = "C++ AES encryption/decryption module for Python";
    
    m.def("encrypt", &py_encrypt_data,
          py::arg("key"),
          py::arg("iv"),
          py::arg("plaintext"),
          py::arg("mode") = "CBC",
          py::arg("padding") = "PKCS7",
          "Encrypt data using AES with specified mode and padding\n\n"
          "Args:\n"
          "    key: 16-byte key for AES-128\n"
          "    iv: 16-byte initialization vector (ignored for ECB mode)\n"
          "    plaintext: bytes to encrypt\n"
          "    mode: cipher mode (ECB, CBC, CFB, OFB, CTR)\n"
          "    padding: padding mode (ZERO, DES, SF/PKCS7)\n\n"
          "Returns:\n"
          "    Encrypted ciphertext as bytes"
    );
    
    m.def("decrypt", &py_decrypt_data,
          py::arg("key"),
          py::arg("iv"),
          py::arg("ciphertext"),
          py::arg("mode") = "CBC",
          py::arg("padding") = "PKCS7",
          "Decrypt data using AES with specified mode and padding\n\n"
          "Args:\n"
          "    key: 16-byte key for AES-128\n"
          "    iv: 16-byte initialization vector (ignored for ECB mode)\n"
          "    ciphertext: bytes to decrypt\n"
          "    mode: cipher mode (ECB, CBC, CFB, OFB, CTR)\n"
          "    padding: padding mode (ZERO, DES, SF/PKCS7)\n\n"
          "Returns:\n"
          "    Decrypted plaintext as bytes"
    );
}
