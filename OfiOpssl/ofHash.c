#include "ofHash.h"

#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

static int _update(OfHash *hashS, const unsigned char *str, int strlen);
static int getHashLen(HashType type);
static Cbuffer * binToStr(const unsigned char *md, HashType type);

OfHash *initOfHash(HashType type)
{
    OfHash *hashS = (OfHash *)malloc(sizeof(OfHash));
    if (!hashS)
        return NULL;

    hashS->_type = type;
    switch (type)
    {
    case (Md5):
        MD5_Init((MD5_CTX *)&hashS->_ctx.md5);
        break;
    case (Sha1):
        SHA1_Init((SHA_CTX *)&hashS->_ctx.sha1);
        break;
    case (Sha224):
        SHA224_Init((SHA256_CTX *)&hashS->_ctx.sha_224_256);
        break;
    case (Sha256):
        SHA256_Init((SHA256_CTX *)&hashS->_ctx.sha_224_256);
        break;
    case (Sha384):
        SHA384_Init((SHA512_CTX *)&hashS->_ctx.sha_384_512);
        break;
    case (Sha512):
        SHA512_Init((SHA512_CTX *)&hashS->_ctx.sha_384_512);
        break;
    default:
    {
        if (!hashS)
            free(hashS);
        return NULL;
    }
    }

    return hashS;
}

void freeOfHash(OfHash **hashS)
{
    if (hashS==NULL || *hashS==NULL)
        free(*hashS);
    *hashS = NULL;
}

int updateOfHash(OfHash *hashS, const unsigned char *str,int len)
{
    int t = len / s_bashDataSize;

    for (int i = 0; i < t; i++)
    {
        if (_update(hashS, str + (i * s_bashDataSize), s_bashDataSize))
            return -1;
    }

    if (len % s_bashDataSize == 0)
        return 0;

    return _update(hashS, str + (t * s_bashDataSize), len % s_bashDataSize);
}

int _update(OfHash *hashS, const unsigned char *str, int strlen)
{
    int ret = -1;

    switch (hashS->_type)
    {
    case (Md5):
        ret = MD5_Update((MD5_CTX *)&hashS->_ctx.md5, str, (size_t)strlen);
        break;
    case (Sha1):
        ret = SHA1_Update((SHA_CTX *)&hashS->_ctx.sha1, str, (size_t)strlen);
        break;
    case (Sha224):
        ret = SHA224_Update((SHA256_CTX *)&hashS->_ctx.sha_224_256, str, (size_t)strlen);
        break;
    case (Sha256):
        ret = SHA256_Update((SHA256_CTX *)&hashS->_ctx.sha_224_256, str, (size_t)strlen);
        break;
    case (Sha384):
        ret = SHA384_Update((SHA512_CTX *)&hashS->_ctx.sha_384_512, str, (size_t)strlen);
        break;
    case (Sha512):
        ret = SHA512_Update((SHA512_CTX *)&hashS->_ctx.sha_384_512, str, (size_t)strlen);
    default:
        break;
    }

    if (ret == 1)
        return 0;
    return -1;
}
Cbuffer * getHashOfHash(OfHash *hashS)
{
    int mdLen = getHashLen(hashS->_type) + 1;
    unsigned char *md = (unsigned char *)malloc((size_t)mdLen);
    md[0] = '\0';
    md[mdLen] = '\0';

    int ret = -1;

    switch (hashS->_type)
    {
    case (Md5):
        ret = MD5_Final(md, (MD5_CTX *)&hashS->_ctx.md5);
        MD5_Init((MD5_CTX *)&hashS->_ctx.md5);
        break;
    case (Sha1):
        ret = SHA1_Final(md, (SHA_CTX *)&hashS->_ctx.sha1);
        SHA1_Init((SHA_CTX *)&hashS->_ctx.sha1);
        break;
    case (Sha224):
        ret = SHA224_Final(md, (SHA256_CTX *)&hashS->_ctx.sha_224_256);
        SHA224_Init((SHA256_CTX *)&hashS->_ctx.sha_224_256);
        break;
    case (Sha256):
        ret = SHA256_Final(md, (SHA256_CTX *)&hashS->_ctx.sha_224_256);
        SHA256_Init((SHA256_CTX *)&hashS->_ctx.sha_224_256);
        break;
    case (Sha384):
        ret = SHA384_Final(md, (SHA512_CTX *)&hashS->_ctx.sha_384_512);
        SHA384_Init((SHA512_CTX *)&hashS->_ctx.sha_384_512);
        break;
    case (Sha512):
        ret = SHA512_Final(md, (SHA512_CTX *)&hashS->_ctx.sha_384_512);
        SHA512_Init((SHA512_CTX *)&hashS->_ctx.sha_384_512);
    default:
        break;
    }

    if (ret != 1)
    {
        free(md);
        return NULL;
    }

    Cbuffer *cs = binToStr(md, hashS->_type);
    free(md);

    return cs;
}

Cbuffer * getHashStr(const unsigned char *input, int inputSize, HashType type)
{
    union Hash_CTX_Data ctx;
    int mdLen = getHashLen(type) + 1;
    unsigned char *md = (unsigned char *)malloc((size_t)mdLen);
    md[0] = '\0';
    md[mdLen] = '\0';

    int ret = -1;

    switch (type)
    {
    case (Md5):
        ret = MD5_Init((MD5_CTX *)&ctx.md5);
        if (ret == 1)
            ret = MD5_Update((MD5_CTX *)&ctx.md5, input, (size_t)inputSize);
        if (ret == 1)
            ret = MD5_Final(md, (MD5_CTX *)&ctx.md5);
        break;
    case (Sha1):
        ret = SHA1_Init((SHA_CTX *)&ctx.sha1);
        if (ret == 1)
            ret = SHA1_Update((SHA_CTX *)&ctx.sha1, input, (size_t)inputSize);
        if (ret == 1)
            ret = SHA1_Final(md, (SHA_CTX *)&ctx.sha1);
        break;
    case (Sha224):
        ret = SHA224_Init((SHA256_CTX *)&ctx.sha_224_256);
        if (ret == 1)
            ret = SHA224_Update((SHA256_CTX *)&ctx.sha_224_256, input, (size_t)inputSize);
        if (ret == 1)
            ret = SHA224_Final(md, (SHA256_CTX *)&ctx.sha_224_256);
        break;
    case (Sha256):
        ret = SHA256_Init((SHA256_CTX *)&ctx.sha_224_256);
        if (ret == 1)
            ret = SHA256_Update((SHA256_CTX *)&ctx.sha_224_256, input, (size_t)inputSize);
        if (ret == 1)
            ret = SHA256_Final(md, (SHA256_CTX *)&ctx.sha_224_256);
        break;
    case (Sha384):
        ret = SHA384_Init((SHA512_CTX *)&ctx.sha_384_512);
        if (ret == 1)
            ret = SHA384_Update((SHA512_CTX *)&ctx.sha_384_512, input, (size_t)inputSize);
        if (ret == 1)
            ret = SHA384_Final(md, (SHA512_CTX *)&ctx.sha_384_512);
        break;
    case (Sha512):
        ret = SHA512_Init((SHA512_CTX *)&ctx.sha_384_512);
        if (ret == 1)
            ret = SHA512_Update((SHA512_CTX *)&ctx.sha_384_512, input, (size_t)inputSize);
        if (ret == 1)
            ret = SHA512_Final(md, (SHA512_CTX *)&ctx.sha_384_512);
        break;
    default:
        break;
    }

    if (ret != 1)
    {
        free(md);
        return NULL;
    }

    Cbuffer *cs= binToStr(md, type);
    free(md);

    return cs;
}

Cbuffer * getFileHashStr(const char *fileName, HashType type)
{
    int fd = open(fileName, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;

    struct stat statbuf;
    if (fstat(fd, &statbuf) == 0)
    {
        if (S_ISDIR(statbuf.st_mode))
        {
            close(fd);
            return NULL;
        }
    }
    else
    {
        close(fd);
        return NULL;
    }

    OfHash *of = initOfHash(type);

    char buf[s_bashDataSize + 1];
    int readSize = 0;
    while (1)
    {
        readSize = (int)read(fd, (void *)buf, sizeof(buf));
        if(readSize==0)
            break;

        if (readSize < 0)
        {
            close(fd);
            freeOfHash(&of);
            NULL;
        }

        if (_update(of, (const unsigned char *)buf, readSize))
        {
            close(fd);
            freeOfHash(&of);
            NULL;
        }
    }

    close(fd);
    Cbuffer *cs = getHashOfHash(of);
    freeOfHash(&of);
    return cs;
}

int getHashLen(HashType type)
{
    int ret = MD5_DIGEST_LENGTH;
    switch (type)
    {
    case (Md5):
        ret = MD5_DIGEST_LENGTH;
        break;
    case (Sha1):
        ret = SHA_DIGEST_LENGTH;
        break;
    case (Sha224):
        ret = SHA224_DIGEST_LENGTH;
        break;
    case (Sha256):
        ret = SHA256_DIGEST_LENGTH;
        break;
    case (Sha384):
        ret = SHA384_DIGEST_LENGTH;
        break;
    case (Sha512):
        ret = SHA512_DIGEST_LENGTH;
        break;
    default:
        break;
    }

    return ret;
}

Cbuffer * binToStr(const unsigned char *md, HashType type)
{
    int bufLen = getHashLen(type) * 2 + 1;

    char *buf = (char *)malloc((size_t)bufLen);
    buf[bufLen] = '\0';

    for (int i = 0; i < bufLen / 2; i++)
    {
        sprintf(buf + 2 * i, "%02x", *(md + i));
    }

    Cbuffer *cs= (Cbuffer *)malloc(sizeof(Cbuffer));
    cs->data=(unsigned char *)buf;
    cs->size=bufLen - 1;

    return cs;
}