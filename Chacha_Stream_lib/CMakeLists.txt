add_library(Chacha_Stream_lib STATIC
            src/Chacha_Stream_lib.cpp)

target_include_directories(
    Chacha_Stream_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_link_libraries(Chacha_Stream_lib PUBLIC crypto++)

add_library(FileEncryptor::ChachaStream ALIAS Chacha_Stream_lib)