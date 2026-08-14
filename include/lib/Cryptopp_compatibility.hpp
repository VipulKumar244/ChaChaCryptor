#pragma once

#if __has_include(<cryptopp/chacha.h>)
    #include<cryptopp/chacha.h>
    #include<cryptopp/osrng.h>
    #include<cryptopp/pwdbased.h>
    #include<cryptopp/sha.h>

#elif __has_include(<crypto++/chacha.h)
    #include<crypto++/chacha.h>
    #include<crypto++/osrng.h>
    #include<crypto++/pwdbased.h>
    #include<crypto++/sha.h>


#else
    #error "Crypto++ headers not found.Install libcrypto++-dev(Debian/Ubuntu),"\
            "cryptopp (Homebrew/Fedora/Arch) or the cryptopp vcpkg port."








#endif