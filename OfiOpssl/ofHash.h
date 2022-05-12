#ifndef OFILM_OPSSL_H
#define OFILM_OPSSL_H

#include <string.h>

#include "common_st.h"

typedef enum HashType
{
    Md5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5
} HashType;

typedef struct MD5state_st_n
{
    unsigned int A, B, C, D;
    unsigned int Nl, Nh;
    unsigned int data[64];
    unsigned int num;
} MD5_CTX_n;

typedef struct SHAstate_st_n
{
    unsigned int h0, h1, h2, h3, h4;
    unsigned int Nl, Nh;
    unsigned int data[16];
    unsigned int num;
} SHA_CTX_n;

typedef struct SHA256state_st_n
{
    unsigned int h[8];
    unsigned int Nl, Nh;
    unsigned int data[16];
    unsigned int num, md_len;
} SHA256_CTX_n;

typedef struct SHA512state_st_n
{
    unsigned long long h[8];
    unsigned long long Nl, Nh;
    union
    {
        unsigned long long d[16];
        unsigned char p[128];
    } u;
    unsigned int num, md_len;
} SHA512_CTX_n;

static const int s_bashDataSize = 1024;

typedef struct OfHash
{

    union Hash_CTX_Data
    {
        MD5_CTX_n md5;
        SHA_CTX_n sha1;
        SHA256_CTX_n sha_224_256;
        SHA512_CTX_n sha_384_512;
    } _ctx;

    enum HashType _type;
} OfHash;

OfHash *initOfHash(HashType type);
void freeOfHash(OfHash **hashS);
int updateOfHash(OfHash *hashS, const unsigned char *str,int len);
Cbuffer * getHashOfHash(OfHash *hashS);
Cbuffer * getHashStr(const unsigned char *input,int inputSize,HashType type);
Cbuffer * getFileHashStr(const char *fileName, HashType type);

#endif
