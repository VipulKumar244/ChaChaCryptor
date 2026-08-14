#include<lib/Chacha_Stream.hpp>

namespace pfe{
    ChaChaCipher::ChaChaCipher(const key&key,const nonce&nonce){
        cipher_.SetKeyWithIV(
            key.data(),key.size(),
            nonce.data(),nonce.size()
        );
    }

    void ChaChaCipher:: apply(std::span<std::uint8_t>buf,std::uint64_t stream_offset){
        cipher_.Seek(stream_offset);
        auto* p=reinterpret_cast<CryptoPP::byte*>(buf.data());
        cipher_.ProcessData(p,p,buf.size());
    }


}