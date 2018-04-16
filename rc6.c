/*
// RC6 & RC5 block cipher supporting unusual block sizes.
//
// Written by Ted Krovetz (ted@krovetz.net). Modified April 10, 2018.
//
// RC6 and RC5 were both patented and trademarked around the time
// each was invented. The author of this code believes the patents
// have expired and that the trademarks may still be in force. Seek
// legal advice before using RC5 or RC6 in any project.
//
// This is free and unencumbered software released into the public
// domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a
// compiled binary, for any purpose, commercial or non-commercial,
// and by any means.
//
// In jurisdictions that recognize copyright laws, the author or
// authors of this software dedicate any and all copyright interest
// in the software to the public domain. We make this dedication for
// the benefit of the public at large and to the detriment of our
// heirs and successors. We intend this dedication to be an overt act
// of relinquishment in perpetuity of all present and future rights
// to this software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
*/

/* Requirements of this implementation:
 * - At compile-time: WORD_SZ must be set to one of 8/16/32/64/128.
 * - At run-time: w==WORD_SZ, r%4==0, and both b and r in 0..255.
 * - All pointers (except user key) must be okay for WORD read/write.
 * - GCC extensions: __builtin_bswap32, __builtin_bswap64, __int128.
 *
 * Note: For faster performance unroll loops (eg, gcc -O3).
 */
 
#include <stdint.h>
#include "rc6.h"

#define WORD_SZ 64        /* word size bits, one of 8/16/32/64/128 */

/* Definitions for each supported word size. Some GCC-specific.    */
#if WORD_SZ==8
    typedef uint8_t WORD;
    const int LGW = 3;
    const WORD P = UINT8_C(0xb7), Q = UINT8_C(0x9f);
    static WORD bswap(WORD x) { return x; }
#elif WORD_SZ==16
    typedef uint16_t WORD;
    const int LGW = 4;
    const WORD P = UINT16_C(0xb7e1), Q = UINT16_C(0x9e37);
    static WORD bswap(WORD x) { return x<<8 | x>>8; }
#elif WORD_SZ==32
    typedef uint32_t WORD;
    const int LGW = 5;
    const WORD P = UINT32_C(0xb7e15163), Q = UINT32_C(0x9e3779b9);
    static WORD bswap(WORD x) { return __builtin_bswap32(x); }
#elif WORD_SZ==64
    typedef uint64_t WORD;
    const int LGW = 6;
    const WORD P = UINT64_C(0xb7e151628aed2a6b),
               Q = UINT64_C(0x9e3779b97f4a7c15);
    static WORD bswap(WORD x) { return __builtin_bswap64(x); }
#elif WORD_SZ==128
    typedef unsigned __int128 WORD;
    const int LGW = 7;
    const WORD P = ((WORD)UINT64_C(0xb7e151628aed2a6a) << 64) |
                          UINT64_C(0xbf7158809cf4f3c7);
    const WORD Q = ((WORD)UINT64_C(0x9e3779b97f4a7c15) << 64) |
                          UINT64_C(0xf39cc0605cedc835);
    static WORD bswap(WORD x) { return __builtin_bswap64(x >> 64) |
                                ((WORD)__builtin_bswap64(x) << 64); }
#else
    #error -- WORD_SZ must be 8, 16, 32, 64, or 128
#endif

static int max(int a, int b) { return (a>b ? a : b); }
static WORD rotl(WORD x, int d) { return (x<<d)|(x>>(WORD_SZ-d)); }
static WORD rotr(WORD x, int d) { return (x>>d)|(x<<(WORD_SZ-d)); }
static WORD bswap_if_be(WORD x) {
    const union { unsigned x; unsigned char endian; } little = { 1 };
    return (little.endian ? x : bswap(x));
}

static int setup(WORD *S, int S_words,
                     int w, int r, int b, void *key) {
    if ((WORD_SZ!=w)||(b<0)||(b>255)||(r<0)||(r>255)||(r%4!=0)) {
        return -1;
    } else {
        WORD A=0, B=0, L[256/sizeof(WORD)];
        int i, j, k, L_words=max(1, (b+sizeof(WORD)-1)/sizeof(WORD));
        /* Convert key bytes to key words */
        L[L_words-1] = 0;
        for (i=0; i<b; i++) ((char *)L)[i] = ((char *)key)[i];
        for (i=0; i<L_words; i++) L[i] = bswap_if_be(L[i]);
        /* Fill S with constants */
        S[0] = P;
        for (i=1; i<S_words; i++) S[i] = S[i-1] + Q;
        /* Mix key into S */
        for (i=0,j=0,k=0; k<3*max(L_words, S_words); i++,j++,k++) {
            if (i==S_words) i=0;
            if (j==L_words) j=0;
            A = S[i] = rotl(S[i]+A+B, 3);
            B = L[j] = rotl(L[j]+A+B, (A+B) % WORD_SZ);
        }
        return 0;
    }
}
/* Assumes rkey alignment okay for WORD read/write                 */
int rc5_setup(void *rkey, int w, int r, int b, void *key) {
    return setup((WORD *)rkey, 2*r+2, w, r, b, key);
}
int rc6_setup(void *rkey, int w, int r, int b, void *key) {
    return setup((WORD *)rkey, 2*r+4, w, r, b, key);
}

void rc5_encrypt(void *rkey, int w, int r, void *pt, void *ct) {
    int i,j;
    WORD *S=(WORD *)rkey, *p=(WORD *)pt, *c=(WORD *)ct;
    WORD A = bswap_if_be(p[0]) + *(S++);
    WORD B = bswap_if_be(p[1]) + *(S++);
    for (i=0; i<r/4; i++) {
        for (j=0; j<4; j++) {           
            A = rotl(A^B, B % WORD_SZ) + *(S++);
            B = rotl(B^A, A % WORD_SZ) + *(S++);
        }
    }
    c[0] = bswap_if_be(A);
    c[1] = bswap_if_be(B);
}

void rc5_decrypt(void *rkey, int w, int r, void *ct, void *pt) {
    int i,j;
    WORD *S=(WORD *)rkey+2*r+1, *p=(WORD *)pt, *c=(WORD *)ct;
    WORD B = bswap_if_be(c[1]);
    WORD A = bswap_if_be(c[0]);
    for (i=0; i<r/4; i++) {
        for (j=0; j<4; j++) {           
            B = rotr(B - *(S--), A % WORD_SZ)^A;
            A = rotr(A - *(S--), B % WORD_SZ)^B;
        }
    }
    p[1] = bswap_if_be(B - *(S--));
    p[0] = bswap_if_be(A - *S);
}

void rc6_encrypt(void *rkey, int w, int r, void *pt, void *ct) {
    int i,j;
    WORD t, u, *S=(WORD *)rkey, *p=(WORD *)pt, *c=(WORD *)ct;
    WORD A = bswap_if_be(p[0]);
    WORD B = bswap_if_be(p[1]) + *(S++);
    WORD C = bswap_if_be(p[2]);
    WORD D = bswap_if_be(p[3]) + *(S++);
    for (i=0; i<r/4; i++) {
        for (j=0; j<4; j++) {           
            t = rotl(B * (2*B+1), LGW);
            u = rotl(D * (2*D+1), LGW);
            A = rotl(A^t, u % WORD_SZ) + *(S++);
            C = rotl(C^u, t % WORD_SZ) + *(S++);
            t=A; A=B; B=C; C=D; D=t;
        }
    }
    c[0] = bswap_if_be(A + *(S++));
    c[1] = bswap_if_be(B);
    c[2] = bswap_if_be(C + *S);
    c[3] = bswap_if_be(D);
}

void rc6_decrypt(void *rkey, int w, int r, void *ct, void *pt) {
    int i,j;
    WORD t, u, *S=(WORD *)rkey+2*r+3, *p=(WORD *)pt, *c=(WORD *)ct;
    WORD D = bswap_if_be(c[3]);
    WORD C = bswap_if_be(c[2]) - *(S--);
    WORD B = bswap_if_be(c[1]);
    WORD A = bswap_if_be(c[0]) - *(S--);
    for (i=0; i<r/4; i++) {
        for (j=0; j<4; j++) {
            t=D; D=C; C=B; B=A; A=t;
            u = rotl(D * (2*D+1), LGW);
            t = rotl(B * (2*B+1), LGW);
            C = rotr(C - *(S--), t % WORD_SZ)^u;
            A = rotr(A - *(S--), u % WORD_SZ)^t;
        }
    }
    p[3] = bswap_if_be(D - *(S--));
    p[2] = bswap_if_be(C);
    p[1] = bswap_if_be(B - *S);
    p[0] = bswap_if_be(A);
}
