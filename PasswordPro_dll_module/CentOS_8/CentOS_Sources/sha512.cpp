// sha512.cpp
//
#define _CRT_SECURE_NO_WARNINGS

#include "stdafx.h"   // to sha512.h
#include "sha512.h"

/*
#include <cstring>
#include <fstream>    // to stdfx
#include "Modules.h"    // to stdfx

#include <inttypes.h>


//#include <endian.h>
//#include <errno.h>
//#include <limits.h>
//
//#include <stdbool.h>
//#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//
//#include <stddef.h>


//#define NULL ((void *)0)
//#define NULL 0;

//#ifndef _CRT_SECURE_NO_WARNINGS
//#define _CRT_SECURE_NO_WARNINGS
//#endif // ! No warning "strncpy"
*/

/* Define our magic string to mark salt for SHA512 "encryption"
   replacement.  */
static const char sha512_salt_prefix[] = "$6$";

/* Prefix for optional rounds specification.  */
static const char sha512_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* Table with characters for base64 transformation.  */
 //static const char b64t[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
 static const char b64t[64] = { 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
     0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
     0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
     0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
     0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A };

//#if __BYTE_ORDER == __LITTLE_ENDIAN
# define SWAP(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))
//#else
//# define SWAP(n) (n)
//#endif



/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.2)  */
unsigned char fillbuf[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Constants for SHA512 from FIPS 180-2:4.2.3.  */
const unsigned long long K[80] = //ULL = uint64  // SHA512::sha512_k
{ 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL };


/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.3)  */
void sha512_init_ctx(sha512_ctx_alt*ctx)
{
    ctx->H[0] = 0x6a09e667f3bcc908ULL;
    ctx->H[1] = 0xbb67ae8584caa73bULL;
    ctx->H[2] = 0x3c6ef372fe94f82bULL;
    ctx->H[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->H[4] = 0x510e527fade682d1ULL;
    ctx->H[5] = 0x9b05688c2b3e6c1fULL;
    ctx->H[6] = 0x1f83d9abfb41bd6bULL;
    ctx->H[7] = 0x5be0cd19137e2179ULL;
    ctx->total[0] = ctx->total[1] = 0;
    ctx->buflen = 0;
}

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 128 == 0.  */
void sha512_process_block(const void* buffer, size_t len, sha512_ctx_alt* ctx) //void* 
{
    uint64_t* words = (uint64_t*) buffer;
    size_t nwords = len / sizeof(uint64_t);
    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];

    /* First increment the byte count.  FIPS 180-2 specifies the possible
       length of the file up to 2^128 bits.  Here we only compute the
       number of bytes.  Do a double word increment.  */
    ctx->total[0] += len;
    if (ctx->total[0] < len)
        ++ctx->total[1];

    /* Process all bytes in the buffer with 128 bytes in each round of
       the loop.  */
    while (nwords > 0)
    {
        uint64_t W[80];
        uint64_t a_save = a;
        uint64_t b_save = b;
        uint64_t c_save = c;
        uint64_t d_save = d;
        uint64_t e_save = e;
        uint64_t f_save = f;
        uint64_t g_save = g;
        uint64_t h_save = h;

        /* Operators defined in FIPS 180-2:4.1.2.  */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC (x, 28) ^ CYCLIC (x, 34) ^ CYCLIC (x, 39))
#define S1(x) (CYCLIC (x, 14) ^ CYCLIC (x, 18) ^ CYCLIC (x, 41))
#define R0(x) (CYCLIC (x, 1) ^ CYCLIC (x, 8) ^ (x >> 7))
#define R1(x) (CYCLIC (x, 19) ^ CYCLIC (x, 61) ^ (x >> 6))

      /* It is unfortunate that C does not provide an operator for
     cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) ((w >> s) | (w << (64 - s)))

     /* Compute the message schedule according to FIPS 180-2:6.3.2 step 2.  */
        for (unsigned int t = 0; t < 16; ++t)
        {
            W[t] = SWAP(*words);
            ++words;
        }
        for (unsigned int t = 16; t < 80; ++t)
            W[t] = R1(W[t - 2]) + W[t - 7] + R0(W[t - 15]) + W[t - 16];

        /* The actual computation according to FIPS 180-2:6.3.2 step 3.  */
        for (unsigned int t = 0; t < 80; ++t)
        {
            uint64_t T1 = h + S1(e) + Ch(e, f, g) + K[t] + W[t];
            uint64_t T2 = S0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        /* Add the starting values of the context according to FIPS 180-2:6.3.2
       step 4.  */
        a += a_save;
        b += b_save;
        c += c_save;
        d += d_save;
        e += e_save;
        f += f_save;
        g += g_save;
        h += h_save;

        /* Prepare for the next round.  */
        nwords -= 16;
    }

    /* Put checksum in context given as argument.  */
    ctx->H[0] = a;
    ctx->H[1] = b;
    ctx->H[2] = c;
    ctx->H[3] = d;
    ctx->H[4] = e;
    ctx->H[5] = f;
    ctx->H[6] = g;
    ctx->H[7] = h;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.
   ==================================================================
   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void*
sha512_finish_ctx(sha512_ctx_alt* ctx, void* resbuf)
{
    /* Take yet unprocessed bytes into account.  */
    uint64_t bytes = ctx->buflen;
    size_t pad;

    /* Now count remaining bytes.  */
    ctx->total[0] += bytes;
    if (ctx->total[0] < bytes)
        ++ctx->total[1];

    pad = (size_t)(bytes >= 112 ? 128 + 112 - bytes : 112 - bytes);
    memcpy(&ctx->buffer[bytes], fillbuf, pad);

    /* Put the 128-bit file length in *bits* at the end of the buffer.  */
    *(uint64_t*)&ctx->buffer[bytes + pad + 8] = SWAP(ctx->total[0] << 3);
    *(uint64_t*)&ctx->buffer[bytes + pad] = SWAP((ctx->total[1] << 3) |
        (ctx->total[0] >> 61));

    /* Process last bytes.  */
    sha512_process_block(ctx->buffer, (size_t)(bytes + pad + 16), ctx);

    /* Put result from CTX in first 64 bytes following RESBUF.  */
    for (unsigned int i = 0; i < 8; ++i)
        ((uint64_t*)resbuf)[i] = SWAP(ctx->H[i]);

    return resbuf;
}


void
sha512_process_bytes(const void* buffer, size_t len, sha512_ctx_alt* ctx)
{
    /* When we already have some bits in our internal buffer concatenate
       both inputs first.  */
    if (ctx->buflen != 0)
    {
        size_t left_over = (size_t)ctx->buflen;
        size_t add = 256 - left_over > len ? len : 256 - left_over;

        memcpy(&ctx->buffer[left_over], buffer, add);
        ctx->buflen += add;

        if (ctx->buflen > 128)
        {
            sha512_process_block(ctx->buffer, ctx->buflen & ~127, ctx);

            ctx->buflen &= 127;
            /* The regions in the following copy operation cannot overlap.  */
            memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~127],
                (size_t)ctx->buflen);
        }

        buffer = (const char*)buffer + add;
        len -= add;
    }

    /* Process available complete blocks.  */
    if (len >= 128)
    {
#if !_STRING_ARCH_unaligned
        /* To check alignment gcc has an appropriate operator.  Other
           compilers don't.  */
# if __GNUC__ >= 2
#  define UNALIGNED_P(p) (((uintptr_t) p) % alignof (uint64_t) != 0)
# else
#  define UNALIGNED_P(p) (((uintptr_t) p) % sizeof (uint64_t) != 0)
# endif
        if (UNALIGNED_P(buffer))
            while (len > 128)
            {
                sha512_process_block(memcpy(ctx->buffer, buffer, 128), 128,
                    ctx);
                buffer = (const char*)buffer + 128;
                len -= 128;
            }
        else
#endif
        {
            sha512_process_block(buffer, len & ~127, ctx);
            buffer = (const char*)buffer + (len & ~127);
            len &= 127;
        }
    }

    /* Move remaining bytes into internal buffer.  */
    if (len > 0)
    {
        size_t left_over = (size_t)ctx->buflen;

        memcpy(&ctx->buffer[left_over], buffer, len);
        left_over += len;
        if (left_over >= 128)
        {
            sha512_process_block(ctx->buffer, 128, ctx);
            left_over -= 128;
            memcpy(ctx->buffer, &ctx->buffer[128], left_over);
        }
        ctx->buflen = left_over;
    }
}

/*
==========================================================================
*/

//static char*
static char* sha512_crypt_r(SHA512_CTX* context, char* buffer, int buflen)   //,  char* key,  char* salt
{
    //char salt[16];
    //char key[256];
    static char* salt; // = (char*)context->ctSalt; // = context->ctSalt;
    static char* key; // = (char*)context->ctPassw;
    static int buflenSalt;
    static int buflenKey;

    if (buflenSalt != context->ctSaltLen)
    {
        static char* new_buffer = (char*)realloc(salt, context->ctSaltLen);
        if (new_buffer == NULL)
            return NULL; // 0; //NULL;

        salt = new_buffer;
        buflenSalt = context->ctSaltLen;
    }
    if (buflenKey != context->ctPasswLen)
    {
        static void* new_buffer = realloc(key, context->ctPasswLen);
        if (new_buffer == NULL)
            return NULL; // 0; //NULL;

        key = (char*)new_buffer;
        buflenKey = context->ctPasswLen;
    }
    salt = (char*)context->ctSalt; // = context->ctSalt;
    key = (char*)context->ctPassw;

    //memcpy(key, context->ctPassw, context->ctPasswLen);
    //memcpy(salt, context->ctSalt, context->ctSaltLen);

    unsigned char alt_result[64];
        //__attribute__((__aligned__(alignof(uint64_t))));
    unsigned char temp_result[64];
        //__attribute__((__aligned__(alignof(uint64_t))));
    sha512_ctx_alt ctx;
    sha512_ctx_alt alt_ctx;
    size_t salt_len;
    size_t key_len;
    size_t cnt;
    char* cp;
    char* copied_key = NULL;
    char* copied_salt = NULL;
    char* p_bytes;
    char* s_bytes;
    /* Default number of rounds.  */
    size_t rounds = ROUNDS_DEFAULT;
    bool rounds_custom = false;

    /* Find beginning of salt string.  The prefix should normally always
       be present.  Just in case it is not. Если в строке есть $6 */
    if (strncmp(sha512_salt_prefix, salt, sizeof(sha512_salt_prefix) - 1) == 0)
        /* Skip salt prefix.  */
        salt += sizeof(sha512_salt_prefix) - 1;

    // Это если не Соль а Раунды-Соль!  Если в строке есть rounds...
    if (strncmp(salt, sha512_rounds_prefix, sizeof(sha512_rounds_prefix) - 1)
        == 0)
    {
        const char* num = salt + sizeof(sha512_rounds_prefix) - 1;
        char* endp;
        unsigned long int srounds = strtoul(num, &endp, 10);
        if (*endp == '$')
        {
            salt = endp + 1;
            rounds = max(ROUNDS_MIN, min(srounds, ROUNDS_MAX));
            rounds_custom = true;
        }
    }

    salt_len = context->ctSaltLen; // min(strcspn(salt, "$"), SALT_LEN_MAX);
    key_len = context->ctPasswLen; // strlen(key);

    //if ((key - (char*)0) % alignof(uint64_t) != 0)
    //{
    //    char* tmp = (char*)_malloca(key_len + alignof(uint64_t));
    //    key = copied_key =
    //        (char*) memcpy(tmp + alignof(uint64_t)
    //            - (tmp - (char*)0) % alignof(uint64_t),
    //            key, key_len);
    //}

    //if ((salt - (char*)0) % alignof(uint64_t) != 0)
    //{
    //    char* tmp = (char*)_malloca(salt_len + alignof(uint64_t));
    //    salt = copied_salt =
    //        (char*) memcpy(tmp + alignof(uint64_t)
    //            - (tmp - (char*)0) % alignof(uint64_t),
    //            salt, salt_len);
    //}

    /* Prepare for the real work.  */
    sha512_init_ctx(&ctx);

    /* Add the key string.  */
    sha512_process_bytes(key, key_len, &ctx);

    /* The last part is the salt string.  This must be at most 16
       characters and it ends at the first `$' character (for
       compatibility with existing implementations).  */
    sha512_process_bytes(salt, salt_len, &ctx);


    /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
       final result will be added to the first context.  */
    sha512_init_ctx(&alt_ctx);

    /* Add key.  */
    sha512_process_bytes(key, key_len, &alt_ctx);

    /* Add salt.  */
    sha512_process_bytes(salt, salt_len, &alt_ctx);

    /* Add key again.  */
    sha512_process_bytes(key, key_len, &alt_ctx);

    /* Now get result of this (64 bytes) and add it to the other
       context.  */
    sha512_finish_ctx(&alt_ctx, alt_result);

    /* Add for any character in the key one byte of the alternate sum.  */
    for (cnt = key_len; cnt > 64; cnt -= 64)
        sha512_process_bytes(alt_result, 64, &ctx);
    sha512_process_bytes(alt_result, cnt, &ctx);

    /* Take the binary representation of the length of the key and for every
       1 add the alternate sum, for every 0 the key.  */
    for (cnt = key_len; cnt > 0; cnt >>= 1)
        if ((cnt & 1) != 0)
            sha512_process_bytes(alt_result, 64, &ctx);
        else
            sha512_process_bytes(key, key_len, &ctx);

    /* Create intermediate result.  */
    sha512_finish_ctx(&ctx, alt_result);

    /* Start computation of P byte sequence.  */
    sha512_init_ctx(&alt_ctx);

    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < key_len; ++cnt)
        sha512_process_bytes(key, key_len, &alt_ctx);

    /* Finish the digest.  */
    sha512_finish_ctx(&alt_ctx, temp_result);

    /* 16 Create byte sequence P.  */
    cp = p_bytes = (char*)_malloca(key_len);
    cnt = key_len;  // Заглушка для кода ниже
    //for (cnt = key_len; cnt >= 64; cnt -= 64)
    //    cp = mempcpy(cp, temp_result, 64);
    memcpy(cp, temp_result, cnt);

    /* 17 Start computation of S byte sequence.  */
    sha512_init_ctx(&alt_ctx);

    /* 18 For every character in the password add the entire password.  */
    for (cnt = 0; cnt < (unsigned)16 + alt_result[0]; ++cnt)
        sha512_process_bytes(salt, salt_len, &alt_ctx);

    /* 19 Finish the digest.  */
    sha512_finish_ctx(&alt_ctx, temp_result);

    /* 20 Create byte sequence S. У анс соль всегда 16 символов! */
    cnt = salt_len;  // Заглушка для кода ниже
    cp = s_bytes = (char*)_malloca(salt_len);
    //for (cnt = salt_len; cnt >= 64; cnt -= 64)
    //    cp = mempcpy(cp, temp_result, 64);
    memcpy(cp, temp_result, cnt);

    /* Repeatedly run the collected hash value through SHA512 to burn
       CPU cycles.  */
    for (cnt = 0; cnt < rounds; ++cnt)
    {
        /* New context.  */
        sha512_init_ctx(&ctx);

        /* Add key or last result.  */
        if ((cnt & 1) != 0)
            sha512_process_bytes(p_bytes, key_len, &ctx);
        else
            sha512_process_bytes(alt_result, 64, &ctx);

        /* Add salt for numbers not divisible by 3.  */
        if (cnt % 3 != 0)
            sha512_process_bytes(s_bytes, salt_len, &ctx);

        /* Add key for numbers not divisible by 7.  */
        if (cnt % 7 != 0)
            sha512_process_bytes(p_bytes, key_len, &ctx);

        /* Add key or last result.  */
        if ((cnt & 1) != 0)
            sha512_process_bytes(alt_result, 64, &ctx);
        else
            sha512_process_bytes(p_bytes, key_len, &ctx);

        /* Create intermediate result.  */
        sha512_finish_ctx(&ctx, alt_result);
    }

    /* Now we can construct the result string.  It consists of three
       parts.  */
    int shiftBuff;
    cp = buffer;
    memcpy(buffer, sha512_salt_prefix, max(0, buflen)); //cp = strncpy / __stpncpy -> strncpy
    shiftBuff = sizeof(sha512_salt_prefix) - 1;
    buflen -= shiftBuff;

    // Не используем пока Раунды-Соль!
    if (rounds_custom)
    {
        int n = snprintf(cp, max(0, buflen), "%s%zu$",
            sha512_rounds_prefix, rounds);
        cp += n;
        buflen -= n;
    }

    memcpy(&cp[(size_t)shiftBuff], salt, min((size_t)max(0, buflen), salt_len)); // __stpncpy -> strncpy
    shiftBuff += min((size_t)max(0, buflen), salt_len);
    buflen -= shiftBuff;

    if (buflen > 0)
    {
        cp[(size_t)shiftBuff++] = '$';
        --buflen;
    }
    // *cp++ заменил на конструкцию сдвтга указателя
#define b64_from_24bit(B2, B1, B0, N)                               \
  do {                                                              \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);             \
    int n = (N);                                                    \
    while (n-- > 0 && buflen > 0)                                   \
      {                                                             \
      	cp[(size_t)shiftBuff++] = b64t[w & 0x3f];                   \
      	--buflen;                                                   \
      	w >>= 6;                                                    \
      }                                                             \
  } while (0)

    b64_from_24bit(alt_result[0], alt_result[21], alt_result[42], 4);
    b64_from_24bit(alt_result[22], alt_result[43], alt_result[1], 4);
    b64_from_24bit(alt_result[44], alt_result[2], alt_result[23], 4);
    b64_from_24bit(alt_result[3], alt_result[24], alt_result[45], 4);
    b64_from_24bit(alt_result[25], alt_result[46], alt_result[4], 4);
    b64_from_24bit(alt_result[47], alt_result[5], alt_result[26], 4);
    b64_from_24bit(alt_result[6], alt_result[27], alt_result[48], 4);
    b64_from_24bit(alt_result[28], alt_result[49], alt_result[7], 4);
    b64_from_24bit(alt_result[50], alt_result[8], alt_result[29], 4);
    b64_from_24bit(alt_result[9], alt_result[30], alt_result[51], 4);
    b64_from_24bit(alt_result[31], alt_result[52], alt_result[10], 4);
    b64_from_24bit(alt_result[53], alt_result[11], alt_result[32], 4);
    b64_from_24bit(alt_result[12], alt_result[33], alt_result[54], 4);
    b64_from_24bit(alt_result[34], alt_result[55], alt_result[13], 4);
    b64_from_24bit(alt_result[56], alt_result[14], alt_result[35], 4);
    b64_from_24bit(alt_result[15], alt_result[36], alt_result[57], 4);
    b64_from_24bit(alt_result[37], alt_result[58], alt_result[16], 4);
    b64_from_24bit(alt_result[59], alt_result[17], alt_result[38], 4);
    b64_from_24bit(alt_result[18], alt_result[39], alt_result[60], 4);
    b64_from_24bit(alt_result[40], alt_result[61], alt_result[19], 4);
    b64_from_24bit(alt_result[62], alt_result[20], alt_result[41], 4);
    b64_from_24bit(0, 0, alt_result[63], 2);

    if (buflen <= 0)
    {
        errno = ERANGE;
        buffer = NULL;
    }
    else
        cp[(size_t)shiftBuff++] = '\0'; //*cp = '\0';		/* Terminate the string.  */

    ///* Clear the buffer for the intermediate result so that people
    //    attaching to processes or reading core dumps cannot get any
    //    information.  We do it in this way to clear correct_words[]
    //    inside the SHA512 implementation as well.  */
    //sha512_init_ctx(&ctx);
    //sha512_finish_ctx(&ctx, alt_result);
    //memset(temp_result, '\0', sizeof(temp_result));
    //memset(p_bytes, '\0', key_len);
    //if (s_bytes > 0)       // Добавил для исключения ошибки
    //    memset(s_bytes, '\0', 16);
    //memset(&ctx, '\0', sizeof(ctx));
    //memset(&alt_ctx, '\0', sizeof(alt_ctx));
    //if (copied_key != NULL)
    //    memset(copied_key, '\0', key_len);
    //if (copied_salt != NULL)
    //    memset(copied_salt, '\0', salt_len);

    /* Store state in digest  */
    //memcpy(digest, (unsigned*)buffer, 106);
    return buffer;
    // 0 -> 9
    //const char* infoMain = "$6$GsNKoAhykdO0B4Sb$e9fgGX8V.9yrpLGtaB55zuTo3CDUgI89tHS9xTmsjGaGVg6J2.7lQu3u3cHSal3oCVUq4t8VHJTC6qMB/hToY0";
    //memcpy(digest, infoMain, 106);
}

/* This entry point is equivalent to the `crypt' function in Unix
   libcs.  
   Прислать "Пароль" для шифрования и известную нам "Соль"      */
char* sha512_crypt(SHA512_CTX* context)   //,  char* key ,  char* salt)
{
    /* We don't want to have an arbitrary limit in the size of the
       password.  We can compute an upper bound for the size of the
       result in advance and so we can prepare the buffer we pass to
       `sha512_crypt_r'.  */
       //unsigned char* key = info->szPassword;
       //unsigned char* salt = info->szSalt;
    static char* buffer;
    static int buflen;

    int needed = (sizeof(sha512_salt_prefix) - 1
        + sizeof(sha512_rounds_prefix) + 9 + 1
        + (unsigned)context->ctSaltLen + 1 + 86 + 1);     //strlen(Salt)

    if (buflen < needed)
    {
        static char* new_buffer = (char*)realloc(buffer, needed);
        if (new_buffer == NULL)
            return NULL; // 0; //NULL;

        buffer = new_buffer;
        buflen = needed;
    }

    return sha512_crypt_r(context, buffer, buflen);   //, key, salt

    //const char* infoMain = "$6$GsNKoAhykdO0B4Sb$e9fgGX8V.9yrpLGtaB55zuTo3CDUgI89tHS9xTmsjGaGVg6J2.7lQu3u3cHSal3oCVUq4t8VHJTC6qMB/hToY0";
    //memcpy(digest, infoMain, 106);

}

