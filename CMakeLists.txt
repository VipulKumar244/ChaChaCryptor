cmake_minimum_required(VERSION 3.15..3.30)
project(FileEncryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)



add_subdirectory(Chacha_Stream_lib)
add_subdirectory(KDF_lib)

add_executable(main app/main.cpp)

target_link_libraries(main PRIVATE FileEncryptor::KDF)
