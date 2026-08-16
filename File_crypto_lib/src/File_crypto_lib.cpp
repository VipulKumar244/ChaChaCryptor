#include<File_crypto.hpp>


namespace pfe{
    namespace Serializer{
        inline void put_u32le(std::vector<std::uint8_t>&out,std::uint32_t v){
            for(int i=0;i<4;i++)out.push_back(static_cast<std::uint8_t>(v>>(8*i)));

        }
        inline void put_u64le(std::vector<std::uint8_t>&out,std::uint64_t v){
            for(int i=0;i<8;i++)out.push_back(static_cast<std::uint8_t>(v>>(8*i)));
        }
        inline std::uint32_t get_u32le(std::uint8_t*p){
            std::uint32_t v=0;
            for(int i=0;i<4;i++){
                v|=static_cast<std::uint32_t>(p[i])<<(8*i);
            }
            return v;
        }
        inline std::uint64_t get_u64le(std::uint8_t*p){
            std::uint64_t v=0;
            for(int i=0;i<8;i++){
                v|=static_cast<std::uint64_t>(p[i])<<(8*i);
            }
            return v;
        }

    }
    inline nonce random_nonce(){
        nonce nonce{};
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(nonce.data(),nonce.size());
        return nonce;
    }

    inline std::vector<std::uint8_t>serialize_header(const FileHeader&h){

        std::vector<std::uint8_t>out;
        out.reserve(kHeaderSize);
        out.insert(out.end(),kMagic.begin(),kMagic.end());
        out.push_back(kVersion);
        out.insert(out.end(),h.nonce.begin(),h.nonce.end());
        Serializer::put_u32le(out,h.chunk_size);
        Serializer::put_u64le(out,h.original_size);
        return out;

    }

    inline std::expected<FileHeader,CryptoError>parse_header(std::span<const std::uint8_t>buf){
        if(buf.size()<kHeaderSize){
            return std::unexpected(CryptoError::TruncatedInput);
        }
        if(!std::equal(kMagic.begin(),kMagic.end(),buf.begin())){
            return std::unexpected(CryptoError::BadHeader);
        }
        if(buf[4]!=kVersion){
            return std::unexpected(CryptoError::UnsupportedVersion);
        }

        FileHeader h;
        std::copy_n(buf.begin()+5,12,h.nonce.begin());
        h.chunk_size=Serializer::get_u32le(buf.data()+17);
        h.original_size=Serializer::get_u64le(buf.data()+21);
        return h;
    }


}