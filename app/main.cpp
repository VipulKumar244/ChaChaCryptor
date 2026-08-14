#include<lib/Chacha_Stream.hpp>
#include<iostream>
#include<assert.h>
int main(){
    pfe::key secret_key;
    secret_key.fill(0x41);
    pfe::nonce iv_nonce;
    iv_nonce.fill(0x59);
    pfe::ChaChaCipher cipher(secret_key,iv_nonce);

    std::string plain_text="Hello miau!!!!!";
    std::vector<std::uint8_t>buffer(plain_text.begin(),plain_text.end());

    std::vector<std::uint8_t>backup=buffer;

    std::cout<<"Original Text: "<<plain_text<<std::endl;

    std::uint64_t offset=0;
    std::span<std::uint8_t>crypto_span(buffer);

    cipher.apply(crypto_span,offset);
    
    for(auto byte:buffer){
        printf("%02x",byte);
    }
    std::cout<<"\n";

    assert(buffer!=backup&&"Encryption failed");

    std::cout<<"Decrypting";
    offset=0;

    cipher.apply(crypto_span,offset);

    std::string decrypted(buffer.begin(),buffer.end());

    std::cout<<"Recovered: "<<decrypted<<"\n";

    if(buffer==backup){
        std::cout<<"It workd :D";
    }
    else{
        std::cerr<<"Didnt work :(";
        return 1;
    }



}