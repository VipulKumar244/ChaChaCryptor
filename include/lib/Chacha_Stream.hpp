#pragma once






#include<array>
#include<cstdint>
#include<span>
#include<lib/Cryptopp_compatibility.hpp>

namespace pfe{

    using key=std::array<CryptoPP::byte,32>;
    using nonce=std::array<CryptoPP::byte,12>;


    class ChaChaCipher{
        public:
        /*
        - Construct the 4x4 key generator matrix with key and nonce.
        */
            ChaChaCipher(const key&key,const nonce&nonce);

            /*
            - Configure the block counter with offset passed with chunk buffer
            - source- buffer pointer,
            - destination- buffer pointer
            
            */
            void apply(std::span<std::uint8_t>buf,std::uint64_t stream_offset);










        private:
            CryptoPP::ChaChaTLS::Encryption cipher_;



    };




}