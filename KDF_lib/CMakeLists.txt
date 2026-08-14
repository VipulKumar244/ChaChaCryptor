add_library(
    KDF_lib STATIC
    src/KDF_lib.cpp
)
target_include_directories(
    KDF_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

)

target_link_libraries(KDF_lib PUBLIC FileEncryptor::ChachaStream)

add_library(FileEncryptor::KDF ALIAS KDF_lib)