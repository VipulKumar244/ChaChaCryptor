#include<KDF.hpp>
#include<iostream>
#include<assert.h>
#include<fstream>

std::vector<char>encrypt_whole_file(const std::string&filename,pfe::ChaChaCipher &cipher_){
    std::ifstream file(filename,std::ios::binary|std::ios::ate);
    if(!file) {
        std::cerr<<"Could not open the file in the whole encrypt function!!!!";
        return {};
    };
    std::streamsize size=file.tellg();

    file.seekg(0,std::ios::beg);

    std::vector<char>buffer(size);
    file.read(buffer.data(),size);
    cipher_.apply({reinterpret_cast<std::uint8_t*>(buffer.data()),buffer.size()},0);
    return buffer;
}

int main(){

    pfe::key key;
    key.fill(0xAA);
    pfe::nonce nonce;
    nonce.fill(0xAA);
    constexpr std::size_t batch_size=64;
    pfe::ChaChaCipher cipher_(key,nonce);
    std::string filename="test.txt";
    std::vector<char>expected_cipher_text=encrypt_whole_file(filename,cipher_);

    std::ifstream file(filename,std::ios::binary);
    if(!file){
        std::cerr<<"Could not open the file.\n";
        return 1;
    }   

    std::cout<<"Batch testing..\n";
    std::vector<char>buffer(batch_size);
    std::vector<char>batch_ciphertext;
    std::uint64_t current_offset=0;
    while(file.read(buffer.data(),batch_size)||file.gcount()>0){
        std::streamsize bytes_read=file.gcount();
        std::span<std::uint8_t>batch_span(reinterpret_cast<uint8_t*>(buffer.data()),bytes_read);
        cipher_.apply(batch_span,current_offset);
        batch_ciphertext.insert(batch_ciphertext.end(),batch_span.begin(),batch_span.end());
        current_offset+=bytes_read;
    }
    assert(batch_ciphertext==expected_cipher_text && "OFFSET BUG: Batch output mistmatch!!!");

    std::cout<<"Success!!!!";
    return 0;


    
    







}