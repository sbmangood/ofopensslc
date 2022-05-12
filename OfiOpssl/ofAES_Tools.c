#include "ofAES_Tools.h"

#include <openssl/aes.h>
#include <string.h>
#include <malloc.h>

Of_AES_key *initOf_AES_key(unsigned char *key, int size)
{
    static const int skeySize16 = 16;
    static const int skeySize24 = 24;
    static const int skeySize32 = 32;

    Of_AES_key *aeskey = (Of_AES_key *)malloc(sizeof(Of_AES_key));
    aeskey->_key = NULL;

    int s = size;
    int msize = 0;
    int add = 0;

    if (s == skeySize16 || s == skeySize24 || s == skeySize32)
    {
        msize = s;
    }
    else
    {
        if (s < skeySize16)
        {
            msize = skeySize16;
            add = skeySize16 - s;
        }
        else if (s < skeySize24)
        {
            msize = skeySize24;
            add = skeySize24 - s;
        }
        else if (s < skeySize32)
        {
            msize = skeySize32;
            add = skeySize32 - s;
        }
        else if (s > skeySize32)
        {
            msize = skeySize32;
            add = -1;
        }
    }

    aeskey->_key = (unsigned char *)malloc((size_t)(msize + 1));
    aeskey->_key[msize] = '\0';

    if (add >= 0)
    {
        memcpy((void *)aeskey->_key, (const void *)key, (size_t)s);
        for (int i = 0; i < add; i++)
        {
            aeskey->_key[s + i] = '*';
        }
    }
    else
    {
        memcpy((void *)aeskey->_key, (const void *)key, (size_t)msize);
    }

    aeskey->size = msize;

    return aeskey;
}

void freeOf_AES_key(Of_AES_key **key)
{
    if (key == NULL || *key == NULL)
        return;

    if ((*key)->_key != NULL)
        free((*key)->_key);

    (*key)->_key = NULL;
    *key = NULL;
}

Cbuffer *AES_EncrypterEncryptStr(const Of_AES_key *aes_key, const unsigned char *input, int size)
{

    static const char *cbc_init_vc = ")(#$%Hyrqmere413";

    unsigned char *key = aes_key->_key;
    AES_KEY aesKey;
    AES_set_encrypt_key(
        (const unsigned char *)(key),
        aes_key->size * 8,
        &aesKey);

    int srcLen = size + 1;
    int t = srcLen / AES_BLOCK_SIZE;
    if (srcLen % AES_BLOCK_SIZE != 0)
    {
        srcLen = (t + 1) * AES_BLOCK_SIZE + 1;
    }

    unsigned char *outbuf = (unsigned char *)malloc((size_t)srcLen);
    unsigned char vc[AES_BLOCK_SIZE];
    memset(outbuf, 0, (size_t)srcLen);
    memcpy(vc, cbc_init_vc, AES_BLOCK_SIZE);

    for (int i = 0; i < t + 1; i++)
    {
        AES_cbc_encrypt(
            (const unsigned char *)(input + AES_BLOCK_SIZE * i),
            outbuf + AES_BLOCK_SIZE * i,
            AES_BLOCK_SIZE,
            &aesKey,
            (unsigned char *)vc,
            AES_ENCRYPT);
    }

    outbuf[srcLen] = '0';

    Cbuffer *cb = initCbuffer();
    cb->data = outbuf;
    cb->size = srcLen - 1;

    return cb;
}

Cbuffer *AES_DecrypterDecryptStr(const Of_AES_key *aes_key, const unsigned char *input, int size)
{
    static const char *cbc_init_vc = ")(#$%Hyrqmere413";
    unsigned char *key = aes_key->_key;
    AES_KEY aesKey;
    AES_set_decrypt_key(
        (const unsigned char *)(key),
        aes_key->size * 8,
        &aesKey);

    int srcLen = size;
    int t = srcLen / AES_BLOCK_SIZE;

    if (srcLen % AES_BLOCK_SIZE != 0)
    {
        srcLen = (t + 1) * AES_BLOCK_SIZE + 1;
    }

    unsigned char *outbuf = (unsigned char *)malloc((size_t)(srcLen + 1));
    memset(outbuf, 0, (size_t)(srcLen + 1));
    unsigned char vc[AES_BLOCK_SIZE];
    memcpy(vc, (void *)cbc_init_vc, AES_BLOCK_SIZE);
    for (int i = 0; i < t + 1; i++)
    {
        AES_cbc_encrypt(
            (const unsigned char *)(input + AES_BLOCK_SIZE * i),
            outbuf + AES_BLOCK_SIZE * i,
            AES_BLOCK_SIZE,
            &aesKey,
            (unsigned char *)vc,
            AES_DECRYPT);
    }

    Cbuffer *cb = initCbuffer();
    cb->data = outbuf;
    cb->size = srcLen;

    return cb;
}