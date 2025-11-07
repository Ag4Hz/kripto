#include "padding.h"
#include <stdexcept>
#include <algorithm>

bytes apply_padding(const bytes &plain, size_t block_bytes, PaddingMode pm) {
    bytes out = plain;
    size_t rem = plain.size() % block_bytes;

    if (rem == 0) {
        if (pm == PaddingMode::ZERO) {
            // zero-padding: nothing to add if exact multiple
            return out;
        }

        // DES padding and SF both add a full block when exact multiple
        size_t add = block_bytes;
        out.resize(out.size() + add, 0x00); // default fill with zeros
        if (pm == PaddingMode::DES) {
            out[out.size() - add] = 0x80; // bit pattern 1000 0000 as a byte
        } else if (pm == PaddingMode::SF) {
            uint8_t val = static_cast<uint8_t>(add);
            std::fill(out.end() - add, out.end(), val);
        }
        return out;
    }

    size_t add = block_bytes - rem;
    out.resize(out.size() + add, 0x00); // default fill with zeros
    if (pm == PaddingMode::DES) {
        out[out.size() - add] = 0x80;
    } else if (pm == PaddingMode::SF) {
        uint8_t val = static_cast<uint8_t>(add);
        std::fill(out.end() - add, out.end(), val);
    }

    return out;
}

bytes remove_padding(const bytes &padded, size_t block_bytes, PaddingMode pm) {
    if (padded.empty() || padded.size() % block_bytes != 0) throw std::runtime_error("Invalid padded length");
        if (pm == PaddingMode::ZERO) {
            // Remove trailing zeros — ambiguous if original ended with zeros;
            bytes out = padded;
            while (!out.empty() && out.back() == 0x00)
                out.pop_back();
            
                return out;
        } else if (pm == PaddingMode::DES) {
        // find 0x80 from end
        size_t i = padded.size() - 1;
        // skip trailing zeros
        while (i >= 0 && padded[i] == 0x00)
            --i;
        
        if (i < 0) throw std::runtime_error("DES padding not found");
        if (padded[i] != 0x80) throw std::runtime_error("DES padding invalid");
        
        bytes out(padded.begin(), padded.begin() + i);
        return out;
    } else {
        // SF padding
        uint8_t val = padded.back();
        if (val == 0 || val > block_bytes) throw std::runtime_error("Invalid SF padding value");
        for (size_t i = 0; i < val; ++i) {
            if (padded[padded.size() - 1 - i] != val) {
                throw std::runtime_error("Invalid SF padding bytes");
            }
        }

        bytes out(padded.begin(), padded.end() - val);
        return out;
    }
}