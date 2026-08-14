#include <Chacha_Stream.hpp>
#include<iostream>
#include<assert.h>
#include<numeric>
#include<cstdint>
#include<KDF.hpp>
int main(){
    

    std::string pass="Magmr123";
    std::string salt="miau";
    
    pfe::key key=pfe::derive_key(pass,salt);
    for(auto &i:key){
        std::cout<<i;
    }





}
