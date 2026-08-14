cmake_minimum_required(VERSION 3.15...3.30)

project(FileEncryptor LANGUAGES CXX)

add_library(Chacha_Stream_lib STATIC 
            src/Chacha_Stream_lib.cpp 
            include/lib/Chacha_Stream.hpp 
            include/lib/Cryptopp_compatibility.hpp)
target_include_directories(Chacha_Stream_lib PUBLIC include)
target_compile_features(Chacha_Stream_lib PUBLIC cxx_std_23)
target_link_libraries(Chacha_Stream_lib PUBLIC crypto++)

add_executable(main app/main.cpp)
target_link_libraries(main PRIVATE Chacha_Stream_lib)