#pragma once

#include <stddef.h>
#include <linux/types.h>

#if defined(_MSC_VER)
    #include <string.h>
#endif

#if defined(__has_cpp_attribute)
    #define has_cpp_attribute_(attr) __has_cpp_attribute(attr)
#else
    #define has_cpp_attribute_(attr) 0
#endif

#if defined(__has_c_attribute)
    #define has_c_attribute_(attr) __has_c_attribute(attr)
#else
    #define has_c_attribute_(attr) 0
#endif

#if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || \
   (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define target_little_endian_ 1
#else
    #define target_little_endian_ 0
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define force_inline_    inline __attribute__((always_inline))
    #define never_inline_    __attribute__((noinline))
    #define keep_hot_        __attribute__((hot))
    #define keep_cold_       __attribute__((cold))
#elif defined(_MSC_VER)
    #define force_inline_    __forceinline
    #define never_inline_    __declspec(noinline)
    #define keep_hot_
    #define keep_cold_
#else
    #define force_inline_    inline
    #define never_inline_
    #define keep_hot_
    #define keep_cold_
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define memcpy_(dst, src, len) __builtin_memcpy((void*)(dst), (void*)(src), (len))
    #define memset_(dst, src, len) __builtin_memset((void*)(dst), (src), (len))
    #define memcmp_(dst, src, len) __builtin_memcmp((void*)(dst), (void*)(src), (len))
#else
    // includes _MSC_VER
    #define memcpy_(dst, src, len) memcpy((void*)(dst), (void*)(src), (len))
    #define memset_(dst, src, len) memset((void*)(dst), (src), (len))
    #define memcmp_(dst, src, len) memcmp((void*)(dst), (void*)(src), (len))
#endif

#if defined(__cplusplus)
  #define align_64_ alignas(8)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  #define align_64_ _Alignas(8)
#elif defined(_MSC_VER)
  #define align_64_ __declspec(align(8))
#elif defined(__GNUC__) || defined(__clang__)
  #define align_64_ __attribute__((aligned(8)))
#else
  #define align_64_
#endif

#if defined(__cplusplus) && has_cpp_attribute_(likely)
    #define likely_ [[likely]]
    #define unlikely_ [[unlikely]]
#elif !defined(__cplusplus) && has_c_attribute_(likely)
    #define likely_ [[likely]]
    #define unlikely_ [[unlikely]]
#else
    #define likely_
    #define unlikely_
#endif

// eBPF programs are compiled in a restricted, freestanding environment rather
// than against the normal userspace C library and socket helper stack. Because
// of that, BPF-side code should not assume that libc-provided byte-order
// helpers such as ntohs() are available, desirable, or even the clearest way
// to express packet-field decoding. Defining target-endian-aware ntoh16_
// to do the job in BPF envieonment.
#if target_little_endian_
    #define ntoh16_(x) \
        ((__u16)((((__u16)(x) & 0x00FFu) << 8) | \
                 (((__u16)(x) & 0xFF00u) >> 8)))
#else
    #define ntoh16_(x) ((__u16)(x))
#endif

#define load_net16_from_bytes_(src) \
    ((__u16)((((__u16)((src)[0])) << 8) | \
             ((__u16)((src)[1]))))


#if defined(__SSE2__) || defined(_M_X64) || defined(_M_AMD64) || \
    (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
    #define SSE2_ENABLED
#endif
