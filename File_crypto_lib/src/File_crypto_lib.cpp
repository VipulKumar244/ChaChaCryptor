#include<File_crypto.hpp>


namespace pfe{
    namespace Serializer{
        void put_u32le(std::vector<std::uint8_t>&out,std::uint32_t v){
            for(int i=0;i<4;i++)out.push_back(static_cast<std::uint8_t>(v>>(8*i)));

        }
        void put_u64le(std::vector<std::uint8_t>&out,std::uint64_t v){
            for(int i=0;i<8;i++)out.push_back(static_cast<std::uint8_t>(v>>(8*i)));
        }
        std::uint32_t get_u32le(const std::uint8_t*p){
            std::uint32_t v=0;
            for(int i=0;i<4;i++){
                v|=static_cast<std::uint32_t>(p[i])<<(8*i);
            }
            return v;
        }
        std::uint64_t get_u64le(const std::uint8_t*p){
            std::uint64_t v=0;
            for(int i=0;i<8;i++){
                v|=static_cast<std::uint64_t>(p[i])<<(8*i);
            }
            return v;
        }

    }
    nonce random_nonce(){
        nonce nonce{};
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(nonce.data(),nonce.size());
        return nonce;
    }

    std::vector<std::uint8_t>serialize_header(const FileHeader&h){

        std::vector<std::uint8_t>out;
        out.reserve(kHeaderSize);
        out.insert(out.end(),kMagic.begin(),kMagic.end());
        out.push_back(kVersion);
        out.insert(out.end(),h.nonce.begin(),h.nonce.end());
        Serializer::put_u32le(out,h.chunk_size);
        Serializer::put_u64le(out,h.original_size);
        return out;

    }

    std::expected<FileHeader,CryptoError>parse_header(std::span<const std::uint8_t>buf){
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

    void process_chunk(const fs::path&in_path,const fs::path&out_path,const pfe::key&key,const pfe::nonce &nonce
                                ,std::uint64_t data_offset,std::uint64_t chunk_len,std::uint64_t in_file_offset,
                                std::uint64_t out_file_offset){
        std::ifstream in(in_path,std::ios::binary);
        in.seekg(static_cast<std::streamoff>(in_file_offset));
        std::vector<std::uint8_t>buffer(chunk_len);
        in.read(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(chunk_len));

        ChaChaCipher cipher(key,nonce);
        cipher.apply(buffer,data_offset);

        std::fstream out(out_path, std::ios::binary | std::ios::in | std::ios::out);
        out.seekp(static_cast<std::streamoff>(out_file_offset));
        out.write(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(chunk_len));
}



    void run_chunks_parallel(ThreadPool&pool,const fs::path&in_path,const fs::path&out_path,
                                    const key&key,const nonce&nonce,std::uint64_t data_size,
                                    std::uint32_t chunk_size,std::uint64_t in_base_offset,
                                        std::uint64_t out_base_offset){


        std::vector<std::future<void>>futures;
        std::uint64_t num_chunks=(data_size+chunk_size-1)/chunk_size;
        for(std::uint64_t i=0;i<num_chunks;++i){
            std::uint64_t offset=i*chunk_size;
            std::uint64_t len=std::min<std::uint64_t>(chunk_size,data_size-offset);
            futures.push_back(pool.submit([&,offset,len](){
                process_chunk(in_path,out_path,key,nonce,offset,len,in_base_offset+offset,out_base_offset+offset);
            }));
        }
        for(auto&f:futures)f.get();





                                        }


    std::expected<void,CryptoError>encrypt_file(ThreadPool& pool,const fs::path& in_path,const fs::path&out_path,
                                                    const key&key,std::uint32_t chunk_size){


        std::error_code ec;
        auto size=fs::file_size(in_path,ec);
        if(ec){
            return std::unexpected(CryptoError::CannotOpenInput);
        }
        FileHeader header{
            .nonce=random_nonce(),
            .chunk_size=chunk_size,
            .original_size=size
        };
        auto header_bytes=serialize_header(header);

        {

            std::ofstream out(out_path,std::ios::binary|std::ios::trunc);
            if(!out){
                return std::unexpected(CryptoError::CannotCreateOutput);

            }
            out.write(reinterpret_cast<char*>(header_bytes.data()),static_cast<std::streamsize>(header_bytes.size()));
        }

        fs::resize_file(out_path,kHeaderSize+size,ec);
        if(ec)return std::unexpected(CryptoError::CannotCreateOutput);
        run_chunks_parallel(pool,in_path,out_path,key,header.nonce,size,chunk_size,0,kHeaderSize);
        return {};




    }


    std::expected<void,CryptoError>decrypt_file(ThreadPool&pool,const fs::path& in_path,const fs::path&out_path,
                                                        const key&key){
        std::ifstream in(in_path,std::ios::binary);
        if(!in)return std::unexpected(CryptoError::CannotOpenInput);
        std::vector<std::uint8_t>hbuf(kHeaderSize);
        in.read(reinterpret_cast<char*>(hbuf.data()),static_cast<std::streamsize>(kHeaderSize));
        if(in.gcount()!=static_cast<std::streamsize>(kHeaderSize)){
            return std::unexpected(CryptoError::TruncatedInput);}

        in.close();
        auto header=parse_header(hbuf);
        if(!header)return std::unexpected(header.error());
        {
            std::ofstream out(out_path,std::ios::binary|std::ios::trunc);
            if(!out)return std::unexpected(
                CryptoError::CannotCreateOutput
            );
        }


        std::error_code ec;
        fs::resize_file(out_path,header->original_size,ec);
        if(ec)return std::unexpected(CryptoError::CannotCreateOutput);

        run_chunks_parallel(pool,in_path,out_path,key,header->nonce,header->original_size,header->chunk_size,
                            kHeaderSize,0);
        return {};
                                                        }
}
