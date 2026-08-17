#include <File_crypto.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string_view>

namespace {

const char* error_message(pfe::CryptoError error) {
    switch (error) {
    case pfe::CryptoError::CannotOpenInput: return "cannot open input file";
    case pfe::CryptoError::CannotCreateOutput: return "cannot create output file";
    case pfe::CryptoError::BadHeader: return "invalid encrypted-file header";
    case pfe::CryptoError::UnsupportedVersion: return "unsupported encrypted-file version";
    case pfe::CryptoError::TruncatedInput: return "truncated encrypted file";
    }
    return "unknown error";
}

bool files_match(const std::filesystem::path& left, const std::filesystem::path& right) {
    std::error_code error;
    if (std::filesystem::file_size(left, error) != std::filesystem::file_size(right, error) || error) {
        return false;
    }
    std::ifstream a(left, std::ios::binary);
    std::ifstream b(right, std::ios::binary);
    return std::equal(std::istreambuf_iterator<char>(a), std::istreambuf_iterator<char>(),
                      std::istreambuf_iterator<char>(b), std::istreambuf_iterator<char>());
}

} 

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <input-file> <encrypted-file> <decrypted-file> <password>\n";
        return 2;
    }

    const std::filesystem::path input = argv[1];
    const std::filesystem::path encrypted = argv[2];
    const std::filesystem::path decrypted = argv[3];
    if (std::filesystem::absolute(input) == std::filesystem::absolute(encrypted) ||
        std::filesystem::absolute(input) == std::filesystem::absolute(decrypted) ||
        std::filesystem::absolute(encrypted) == std::filesystem::absolute(decrypted)) {
        std::cerr << "Input, encrypted, and decrypted paths must be different.\n";
        return 2;
    }

    const auto key = pfe::derive_key(argv[4], "file-crypto-test");
    const auto workers = std::max(1u, std::thread::hardware_concurrency());
    pfe::ThreadPool pool(workers);

    if (const auto result = pfe::encrypt_file(pool, input, encrypted, key); !result) {
        std::cerr << "Encryption failed: " << error_message(result.error()) << '\n';
        return 1;
    }
    if (const auto result = pfe::decrypt_file(pool, encrypted, decrypted, key); !result) {
        std::cerr << "Decryption failed: " << error_message(result.error()) << '\n';
        return 1;
    }
    if (!files_match(input, decrypted)) {
        std::cerr << "Round-trip test failed: decrypted content differs from the input.\n";
        return 1;
    }

    std::cout << "Round-trip test passed. Encrypted file: " << encrypted << '\n';
    return 0;
}
