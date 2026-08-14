#include <KDF.hpp>

namespace pfe {

key derive_key(std::string_view password, std::string_view salt,
               unsigned int iterations) {
    key derived_key{};
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;

    kdf.DeriveKey(
        derived_key.data(), derived_key.size(), 0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        reinterpret_cast<const CryptoPP::byte*>(salt.data()), salt.size(),
        iterations);
        
    return derived_key;
}

} 
