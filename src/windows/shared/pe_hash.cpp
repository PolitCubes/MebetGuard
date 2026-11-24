#include "pe_hash.hpp"

#include <cstdint>
#include <cstring>

namespace mebet::win {

namespace {

template <typename T>
bool read(const unsigned char* data, std::size_t size, std::size_t off, T& out) {
    if (off > size || size - off < sizeof(T)) return false;
    std::memcpy(&out, data + off, sizeof(T));
    return true;
}

}  // namespace

bool pe_image_hash(const unsigned char* data, std::size_t size, Sha256Digest& out) {
    std::uint16_t mz = 0;
    std::uint32_t pe_off = 0;
    if (!read(data, size, 0, mz) || mz != 0x5A4D) return false;  // "MZ"
    if (!read(data, size, 0x3C, pe_off)) return false;
    std::uint32_t sig = 0;
    if (!read(data, size, pe_off, sig) || sig != 0x00004550) return false;  // "PE\0\0"

    const std::size_t file_header = pe_off + 4;
    std::uint16_t sections = 0, opt_size = 0;
    if (!read(data, size, file_header + 2, sections)) return false;
    if (!read(data, size, file_header + 16, opt_size)) return false;
    const std::size_t opt = file_header + 20;
    std::uint16_t magic = 0;
    if (!read(data, size, opt, magic)) return false;
    std::size_t datadir;  // offset of IMAGE_DATA_DIRECTORY[0]
    if (magic == 0x10B) {
        datadir = opt + 96;  // PE32
    } else if (magic == 0x20B) {
        datadir = opt + 112;  // PE32+
    } else {
        return false;
    }
    const std::size_t checksum = opt + 64;
    const std::size_t certdir = datadir + 4 * 8;  // IMAGE_DIRECTORY_ENTRY_SECURITY
    const std::size_t section_table = opt + opt_size;
    if (certdir + 8 > section_table) return false;

    std::uint32_t size_of_headers = 0;
    if (!read(data, size, opt + 60, size_of_headers)) return false;
    std::size_t end = size_of_headers;
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::size_t s = section_table + static_cast<std::size_t>(i) * 40;
        std::uint32_t raw_size = 0, raw_ptr = 0;
        if (!read(data, size, s + 16, raw_size) || !read(data, size, s + 20, raw_ptr)) return false;
        if (raw_size != 0 && static_cast<std::size_t>(raw_ptr) + raw_size > end) end = static_cast<std::size_t>(raw_ptr) + raw_size;
    }
    if (end > size || end < certdir + 8) return false;

    Sha256 h;
    h.update(data, checksum);
    h.update(data + checksum + 4, certdir - (checksum + 4));
    h.update(data + certdir + 8, end - (certdir + 8));
    out = h.finish();
    return true;
}

}  // namespace mebet::win
