#pragma once

#ifndef SHA512_H
#define SHA512_H
#endif

/* Structure to save state of computation between the single steps. 
    Объявлять как объект класса: SHA512_CTX obj_name;    */
typedef struct {
    char ctPassw[256];  /* Passw */
    char ctSalt[16];    /* Salt */
    int ctPasswLen;     /* PassLen */
    int ctSaltLen;      /* SaltLen */
} SHA512_CTX;

//void SHA512Init(SHA512_CTX* context, unsigned char* szPassword, unsigned char* szSalt, unsigned int nPasswordLen, unsigned int nSaltLen);

struct sha512_ctx_alt {
    uint64_t H[8];      /* Константы - массив.  */
    uint64_t total[2];  /* Total 1 и 2.  */
    uint64_t buflen;    /* Длина буфера.  */
    char buffer[256];	/* NB: always correctly aligned for uint64_t.  */
};

static char* sha512_crypt_r(SHA512_CTX* context, char* buffer, int buflen);    //,  char * key,  char * salt
void* sha512_finish_ctx(sha512_ctx_alt* ctx, void* resbuf);
void sha512_init_ctx(sha512_ctx_alt*ctx);
void sha512_process_block(const void* buffer, size_t len, sha512_ctx_alt* ctx);
void sha512_process_bytes(const void* buffer, size_t len, sha512_ctx_alt* ctx);
char* sha512_crypt(SHA512_CTX* context);  // , char* key, char* salt);
