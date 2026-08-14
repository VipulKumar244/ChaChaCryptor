#include<lib/Chacha_Stream.hpp>
#include<iostream>
#include<assert.h>
#include<numeric>
#include<cstdint>
int main(){
    pfe::key secret_key;
    secret_key.fill(0x41);
    pfe::nonce iv_nonce;
    iv_nonce.fill(0x59);
    pfe::ChaChaCipher cipher(secret_key,iv_nonce);

    std::vector<std::uint8_t>plaintext(200),e1,e2;
    std::iota(plaintext.begin(),plaintext.end(),0);
    e1=plaintext;
    e2=plaintext;

    std::span<std::uint8_t>chunk{e2};
    cipher.apply(e2,0);

    std::span<std::uint8_t>chunk1(reinterpret_cast<uint8_t*>(e1.data()),64);
    cipher.apply(chunk1,0);

    std::span<std::uint8_t>chunk2(reinterpret_cast<uint8_t*>(e1.data())+64,136);
    cipher.apply(chunk2,64);
    bool match=true;
    for(size_t i=0;i<200;i++){
        if(e2[i]!=e1[i]){
            std::cout<<"Mismatch at"<<i<<std::endl;
            match=false;
            break;
        }
    }
    if(match){
        std::cout<<"miau"<<"\n";
    }




}