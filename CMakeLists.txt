cmake_minimum_required(VERSION 3.16)
project(quic_paas_test LANGUAGES CXX)

find_path(MSQUIC_INCLUDE_DIR NAMES msquic.h REQUIRED)
find_library(MSQUIC_LIBRARY NAMES msquic libmsquic.so.2 REQUIRED)
find_package(Threads REQUIRED)

foreach(program IN ITEMS server client)
    add_executable(quic-${program} src/${program}.cpp)
    target_compile_features(quic-${program} PRIVATE cxx_std_20)
    target_compile_options(quic-${program} PRIVATE -Wall -Wextra)
    target_include_directories(quic-${program} SYSTEM PRIVATE "${MSQUIC_INCLUDE_DIR}")
    target_link_libraries(quic-${program} PRIVATE "${MSQUIC_LIBRARY}" Threads::Threads)
endforeach()
