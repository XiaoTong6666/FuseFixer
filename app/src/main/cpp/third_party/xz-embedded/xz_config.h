/* SPDX-License-Identifier: 0BSD */

#ifndef XZ_CONFIG_H
#define XZ_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "linux_xz.h"

#define memeq(a, b, size) (memcmp((a), (b), (size)) == 0)
#define memzero(buf, size) memset((buf), 0, (size))

#define kmalloc(size, flags) malloc(size)
#define kfree(ptr) free(ptr)
#define vmalloc(size) malloc(size)
#define vfree(ptr) free(ptr)
#define GFP_KERNEL 0
#define fallthrough ((void)0)

#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(type, a, b) ((type)((a) < (b) ? (a) : (b)))

static inline uint32_t get_le32(const uint8_t* ptr) {
    return (uint32_t)ptr[0] | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[2] << 16) |
           ((uint32_t)ptr[3] << 24);
}

#endif
