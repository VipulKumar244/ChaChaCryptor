add_library(
    Thread_Pool_lib STATIC
    src/Thread_Pool_lib.cpp
)

target_include_directories(
    Thread_Pool_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)


add_library(FileEncryptor::Thread_Pool ALIAS Thread_Pool_lib)