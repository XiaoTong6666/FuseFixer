cmake_minimum_required(VERSION 3.22.1)

project(fusefixer)

add_library(
    fusefixer
    SHARED
    fusefixer.cpp
    third_party/xz-embedded/xz_dec_stream.c
    third_party/xz-embedded/xz_dec_lzma2.c
    third_party/xz-embedded/xz_crc32.c
)

target_compile_features(fusefixer PRIVATE cxx_std_20)

target_compile_options(
    fusefixer
    PRIVATE
    -Wall
    -Wextra
    -Werror
    -fvisibility=hidden
)

target_include_directories(fusefixer PRIVATE third_party/xz-embedded)

find_library(log-lib log)
find_library(dl-lib dl)
find_library(icu-lib icu)

if(NOT icu-lib)
    message(FATAL_ERROR "libicu.so not found")
endif()

target_link_libraries(fusefixer ${log-lib} ${dl-lib} ${icu-lib})
