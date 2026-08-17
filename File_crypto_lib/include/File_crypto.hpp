#pragma once



#include<algorithm>
#include<cstdint>
#include<cstring>
#include<expected>
#include<filesystem>
#include<fstream>
#include<span>
#include<string>
#include<vector>

#include<KDF.hpp>
#include<Thread_Pool.hpp>


namespace pfe{
    namespace fs=std::filesystem;


    /*
    Decryption headers
    kMagic- 4 bytes identifier
    kversion- version verification(1 byte)
    kDefaultChunkSize- standard batch chunk size(4 bytes)
    kHeaderSize=sum of all above(8 bytes for 64 bit system)+12 bytes for nonce(96 bits)
    

    
    
    */

    inline constexpr std::array<char,4> kMagic={'D','O','G','E'};
    inline constexpr std::uint8_t kVersion=1;
    inline constexpr std::uint32_t kDefaultChunkSize=4u*1024*1024;
    inline constexpr std::size_t kHeaderSize=29;

    enum class CryptoError{
        CannotOpenInput,
        CannotCreateOutput,
        BadHeader,
        UnsupportedVersion,
        TruncatedInput
    };

    struct FileHeader{
        pfe::nonce nonce{};
        std::uint32_t chunk_size=kDefaultChunkSize;
        std::uint64_t original_size=0;
    };

    nonce random_nonce();

    namespace Serializer{
        void put_u32le(std::vector<std::uint8_t>&out,std::uint32_t v);
        void put_u64le(std::vector<std::uint8_t>&out,std::uint64_t v);
        std::uint32_t get_u32le(const std::uint8_t*p);
        std::uint64_t get_u64le(const std::uint8_t*p);
    }

    std::vector<std::uint8_t> serialize_header(const FileHeader&h);
    std::expected<FileHeader,CryptoError>parse_header(std::span<const std::uint8_t>buf);
    void process_chunk(const fs::path& in_path,const fs::path& out_path,
                            const pfe::key& key,const pfe::nonce&nonce,std::uint64_t data_offset,std::uint64_t chunk_len,
                        std::uint64_t in_file_offset,std::uint64_t out_file_offset);
     
    void run_chunks_parallel(ThreadPool& pool,const fs::path& in_path,
                                    const fs::path&out_path,const key&key,const nonce&nonce,
                                    std::uint64_t data_size,std::uint32_t chunk_size,
                                    std::uint64_t in_base_offset,std::uint64_t out_base_offset);
    
    std::expected<void,CryptoError>encrypt_file(ThreadPool&pool,const fs::path&in_path,
                                                        const fs::path&out_path,const key&key,
                                                        std::uint32_t chunk_size=kDefaultChunkSize);
                                                        
     
                                                        

    std::expected<void,CryptoError>decrypt_file(ThreadPool&pool,const fs::path&in_path,
                                                        const fs::path&out_path,const key&key);
                                                        

}
