cmake_minimum_required(VERSION 3.22.1)

project(fusehide)

add_library(
    fusehide
    SHARED
    fusehide.cpp
    fusehide/unicode_policy.cpp
    fusehide/runtime_state.cpp
    fusehide/fuse_wrappers.cpp
    fusehide/elf_utils.cpp
    fusehide/hook_install.cpp
    fusehide/jni_entry.cpp
    third_party/xz-embedded/xz_dec_stream.c
    third_party/xz-embedded/xz_dec_lzma2.c
    third_party/xz-embedded/xz_crc32.c
)

target_compile_features(fusehide PRIVATE cxx_std_20)

target_compile_options(
    fusehide
    PRIVATE
    -Wall
    -Wextra
    -Werror
    -fvisibility=hidden
)

target_include_directories(fusehide PRIVATE third_party/xz-embedded)

find_library(log-lib log)
find_library(dl-lib dl)
find_library(icu-lib icu)

if(NOT icu-lib)
    message(FATAL_ERROR "libicu.so not found")
endif()

target_link_libraries(fusehide ${log-lib} ${dl-lib} ${icu-lib})
