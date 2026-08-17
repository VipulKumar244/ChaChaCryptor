add_library(
    File_crypto_lib STATIC
    src/File_crypto_lib.cpp
)
target_include_directories(
    File_crypto_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

)

target_link_libraries(File_crypto_lib PUBLIC FileEncryptor::KDF FileEncryptor::Thread_Pool)

add_library(FileEncryptor::FileCrypto ALIAS File_crypto_lib)