cmake_minimum_required(VERSION 3.22.1)

project(fusehide)

add_library(
    fusehide
    SHARED
    fusehide.cpp
    fusehide/core/runtime_state.cpp
    fusehide/elf/elf_utils.cpp
    fusehide/filters/dirent_filter.cpp
    fusehide/filters/reply_buf_filter.cpp
    fusehide/hooks/fuse_wrappers.cpp
    fusehide/hooks/hook_install.cpp
    fusehide/jni/jni_entry.cpp
    fusehide/policy/path_policy.cpp
    fusehide/policy/unicode_policy.cpp
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
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_link_options(
    fusehide
    PRIVATE
    -Wl,--as-needed
)

if(NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    target_compile_options(fusehide PRIVATE
        -Oz
        -flto=full
        -ffunction-sections
        -fdata-sections
        $<$<COMPILE_LANGUAGE:CXX>:-fno-unwind-tables>
        $<$<COMPILE_LANGUAGE:CXX>:-fno-asynchronous-unwind-tables>
        -fno-ident
        -fno-math-errno
        -fomit-frame-pointer
    )

    target_link_options(fusehide PRIVATE
        -flto=full
        -Wl,--gc-sections
        -Wl,--icf=all
        -Wl,--exclude-libs,ALL
        -Wl,-s
        -Wl,--hash-style=gnu
        -Wl,--build-id=none
        -Wl,-Bsymbolic
    )
endif()

target_include_directories(
    fusehide
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    third_party/xz-embedded
)

find_library(log-lib log)
find_library(dl-lib dl)
find_library(icu-lib icu)

if(NOT icu-lib)
    message(FATAL_ERROR "libicu.so not found")
endif()

target_link_libraries(fusehide ${log-lib} ${dl-lib} ${icu-lib})


target_link_options(fusehide PRIVATE -Wl,-z,max-page-size=16384)

add_subdirectory(third_party/Dobby)

add_library(
    zygisk
    SHARED
    zygisk/module.cpp
    zygisk/dex_loader.cpp
    zygisk/dlopen_monitor.cpp
    fusehide/elf/elf_utils.cpp
    third_party/xz-embedded/xz_dec_stream.c
    third_party/xz-embedded/xz_dec_lzma2.c
    third_party/xz-embedded/xz_crc32.c
)

target_compile_features(zygisk PRIVATE cxx_std_20)

target_compile_options(
    zygisk
    PRIVATE
    -Wall
    -Wextra
    -Werror
    -fvisibility=hidden
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_include_directories(
    zygisk
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    third_party/Dobby/include
    third_party/xz-embedded
    zygisk/include
)

target_link_libraries(zygisk dobby_static ${log-lib} ${dl-lib})
target_link_options(zygisk PRIVATE -Wl,-z,max-page-size=16384)
