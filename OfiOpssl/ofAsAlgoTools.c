#include "ofAsAlgoTools.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <malloc.h>

// static Cbuffer *verfierGetDecrptStr(const OfSignVerfier *verfier, const char *input);

struct RSA_Key *initRSA_Key(RSA_keyPtr key)
{
    struct RSA_Key *k = (RSA_Key *)mallocAndSetZero(sizeof(RSA_Key));
    k->_key = key;
    return k;
}

void freeRSA_Key(RSA_Key **key)
{
    if (key == NULL || *key == NULL)
        return;
    if ((*key)->_key != NULL)
        RSA_free((RSA *)(*key)->_key);
    (*key)->_key = NULL;
    free(*key);
    *key = NULL;
}

static RSA_keyPtr getKey(RSA_Key *rsa_key)
{
    return rsa_key->_key;
}

RSA_Keys generateKeys(int pin, int bit)
{

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    BN_set_word(e, (BN_ULONG)pin);
    RSA_generate_key_ex(rsa, bit, e, NULL);

    RSA *pubKey = RSAPublicKey_dup(rsa);
    RSA *priKey = RSAPrivateKey_dup(rsa);

    RSA_Keys rskeys;
    rskeys.privateKey = (RSA_PrivateKey_ptr)mallocAndSetZero(sizeof(RSA_Key));
    rskeys.publicKey = (RSA_PublicKey_ptr)mallocAndSetZero(sizeof(RSA_Key));
    rskeys.publicKey->_key = (RSA_keyPtr)pubKey;
    rskeys.privateKey->_key = (RSA_keyPtr)priKey;

    BN_free(e);
    RSA_free(rsa);

    return rskeys;
}

int storePublicKeyTofile(const char *file, RSA_PublicKey_ptr publicKey, PkSType type)
{
    FILE *fp = fopen(file, "w");
    RSA *rsa = (RSA *)getKey(publicKey);

    if (rsa == NULL)
        return -1;

    int ret = -1;
    if (PkSType_PKCS8 == type)
        ret = PEM_write_RSAPublicKey(fp, rsa);
    else
        ret = PEM_write_RSA_PUBKEY(fp, rsa);

    fclose(fp);
    if (ret == 1)
        return 0;
    return -1;
}

int storePrivateKeyTofile(const char *file, RSA_PrivateKey_ptr privateKey)
{
    FILE *fp = fopen(file, "w");
    RSA *rsa = (RSA *)getKey(privateKey);
    if (rsa == NULL)
        return -1;
    int ret = PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);

    fclose(fp);
    if (ret == 1)
        return 0;

    return -1;
}

Cbuffer *publicKeyTostr(RSA_PublicKey_ptr publicKey, PkSType type)
{

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        return NULL;
    }

    RSA *rsa = (RSA *)getKey(publicKey);
    if (rsa == NULL)
    {
        BIO_free_all(bio);
        return NULL;
    }

    int ret = -1;
    if (PkSType_PKCS8 == type)
        ret = PEM_write_bio_RSAPublicKey(bio, rsa);
    else
        ret = PEM_write_bio_RSA_PUBKEY(bio, rsa);

    if (ret != 1)
    {
        BIO_free_all(bio);
        return NULL;
    }

    int bufLen = BIO_pending(bio) + 1;
    char *buf = mallocAndSetZero(bufLen);
    buf[bufLen - 1] = '\0';

    BIO_read(bio, (void *)buf, bufLen - 1);

    Cbuffer *cs = (Cbuffer *)mallocAndSetZero(sizeof(Cbuffer));
    cs->data = (unsigned char *)buf;
    cs->size = bufLen - 1;

    BIO_free_all(bio);

    return cs;
}

static int subStringEqual(const char *longS, const char *shortS)
{
    int llen = (int)strlen(longS);
    int slen = (int)strlen(shortS);

    if (llen < slen)
        return -1;

    for (int i = 0; i < slen; i++)
    {
        if (longS[i] != shortS[i])
            return -1;
    }

    return 0;
}
RSA_PublicKey_ptr strToPublicKey(const char *pubKey)
{
    BIO *bio = BIO_new_mem_buf((const void *)pubKey, (int)strlen(pubKey));
    RSA *rsa = NULL;

    static const char *pkcs1Head = "-----BEGIN PUBLIC KEY-----";
    
    if (subStringEqual(pubKey, pkcs1Head) != 0)
        rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);
    else
        rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);

    RSA_PublicKey_ptr key = initRSA_Key((RSA_keyPtr)rsa);

    return key;
}

Cbuffer *privateKeyTostr(RSA_PrivateKey_ptr privateKey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        return NULL;
    }

    RSA *rsa = (RSA *)getKey(privateKey);
    if (rsa == NULL)
    {
        BIO_free_all(bio);
        return NULL;
    }

    int ret = PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    if (ret != 1)
    {
        BIO_free_all(bio);
        return NULL;
    }

    int bufLen = BIO_pending(bio) + 1;
    char *buf = (char *)mallocAndSetZero(bufLen);
    buf[bufLen - 1] = '\0';

    BIO_read(bio, (void *)buf, bufLen - 1);
    BIO_free_all(bio);

    Cbuffer *cs = (Cbuffer *)mallocAndSetZero(sizeof(Cbuffer));
    cs->data = (unsigned char *)buf;
    cs->size = bufLen - 1;

    return cs;
}

RSA_PrivateKey_ptr strToPrivateKey(const char *priKey)
{
    int len = (int)strlen(priKey);
    BIO *bio = BIO_new_mem_buf((const void *)priKey, len);
    RSA *rsa = NULL;

    if (bio == NULL)
        return NULL;

    rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);

    RSA_PrivateKey_ptr pk = initRSA_Key((RSA_keyPtr)rsa);

    return pk;
}

RSA_PublicKey_ptr readPublicKeyFromfile(const char *file)
{
    FILE *fp = fopen(file, "r");
    RSA *rsa = RSA_new();

    static const char *pkcs1Head = "-----BEGIN PUBLIC KEY-----";

    int bufLen = (int)strlen(pkcs1Head) + 1;
    char *buf = (char *)mallocAndSetZero(bufLen);
    buf[bufLen - 1] = '\0';

    fgets(buf, bufLen, fp);
    fseek(fp, 0, SEEK_SET);

    if (subStringEqual(pkcs1Head, buf) != 0)
        rsa = PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
    else
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);

    free(buf);

    RSA_PublicKey_ptr pubKey = initRSA_Key((RSA_keyPtr)rsa);

    fclose(fp);
    return pubKey;
}
RSA_PrivateKey_ptr readPrivateKeyFromfile(const char *file)
{
    FILE *fp = fopen(file, "r");
    RSA *rsa = RSA_new();
    rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);

    RSA_PrivateKey_ptr priKey = initRSA_Key((RSA_keyPtr)rsa);

    fclose(fp);
    return priKey;
}

Encrypter initEncrypter(RSA_PublicKey_ptr pubKey)
{
    Encrypter en;
    en._publicKey = pubKey;

    return en;
}

static Cbuffer *encrptStr_private(const Encrypter *en, const unsigned char *srcStr, int size)
{
    RSA *rsa = (RSA *)getKey(en->_publicKey);
    if (rsa == NULL)
        return NULL;
    int keyLen = RSA_size(rsa) + 1;
    char *buf = (char *)mallocAndSetZero(keyLen);
    buf[keyLen] = '\0';
    int ret = RSA_private_encrypt(
        size,
        (const unsigned char *)srcStr,
        (unsigned char *)(buf),
        rsa,
        RSA_PKCS1_PADDING);

    if (ret <= 0)
    {
        free(buf);
        return NULL;
    }

    Cbuffer *cs = (Cbuffer *)mallocAndSetZero(sizeof(Cbuffer));
    // if(ret<keyLen)
    //     buf[ret+1]='\0';
    cs->data = (unsigned char *)buf;
    cs->size = ret;

    return cs;
}

Cbuffer *encrptStr(const Encrypter *en, const Cbuffer *srcStr)
{
    RSA *rsa = (RSA *)getKey(en->_publicKey);
    if (rsa == NULL)
        return NULL;
    int keyLen = RSA_size(rsa) + 1;
    char *buf = (char *)mallocAndSetZero(keyLen);
    buf[keyLen] = '\0';
    int ret = RSA_public_encrypt(
        srcStr->size,
        (const unsigned char *)srcStr->data,
        (unsigned char *)(buf),
        rsa,
        RSA_PKCS1_PADDING);

    if (ret <= 0)
    {
        free(buf);
        return NULL;
    }

    Cbuffer *cs = (Cbuffer *)mallocAndSetZero(sizeof(Cbuffer));
    // if(ret<keyLen)
    //     buf[ret+1]='\0';
    cs->data = (unsigned char *)buf;
    cs->size = ret;

    return cs;
}
Decrypter initDecrypter(RSA_PrivateKey_ptr priKey)
{
    Decrypter de;
    de._privateKey = priKey;

    return de;
}

static Cbuffer *getDecrptStr_public(const Decrypter *de, const unsigned char *input, int size)
{
    RSA *rsa = (RSA *)getKey(de->_privateKey);
    if (rsa == NULL)
        return NULL;
    int keyLen = RSA_size(rsa) + 1;
    char *buf = (char *)mallocAndSetZero(keyLen);
    buf[keyLen] = '\0';

    int ret = RSA_public_decrypt(
        size,
        (const unsigned char *)(input),
        (unsigned char *)buf,
        rsa,
        RSA_PKCS1_PADDING);

    if (ret <= 0)
    {
        free(buf);
        buf = NULL;
        return NULL;
    }
    Cbuffer *cs = (Cbuffer *)mallocAndSetZero(sizeof(Cbuffer));
    cs->data = (unsigned char *)buf;
    cs->size = (int)strlen(buf);

    return cs;
}

Cbuffer *getDecrptStr(const Decrypter *de, const Cbuffer *input)
{
    RSA *rsa = (RSA *)getKey(de->_privateKey);
    if (rsa == NULL)
        return NULL;

    int keyLen = RSA_size(rsa) + 1;
    char *buf = (char *)mallocAndSetZero(keyLen);
    buf[keyLen] = '\0';

    int ret = RSA_private_decrypt(
        input->size,
        (const unsigned char *)(input->data),
        (unsigned char *)buf,
        rsa,
        RSA_PKCS1_PADDING);

    if (ret <= 0)
    {
        free(buf);
        buf = NULL;
        return NULL;
    }
    Cbuffer *cs = (Cbuffer *)mallocAndSetZero(sizeof(Cbuffer));
    cs->data = (unsigned char *)buf;
    cs->size = ret;

    return cs;
}

OfSigner initOfSigner(RSA_PrivateKey_ptr priKey, HashType type)
{
    OfSigner os;
    os._privateKey = priKey;
    os._type = type;

    return os;
}

Cbuffer *getSignStr(const OfSigner *siger, const Cbuffer *srcStr)
{
    OfHash *ofHash = initOfHash(siger->_type);
    if (!ofHash)
        return NULL;
    if (updateOfHash(ofHash, srcStr->data, srcStr->size) != 0)
    {
        freeOfHash(&ofHash);
        return NULL;
    }

    Cbuffer *cs = getHashOfHash(ofHash);
    if (cs == NULL)
    {
        freeOfHash(&ofHash);
        return cs;
    }

    Encrypter en = initEncrypter(siger->_privateKey);

    Cbuffer *retCs = encrptStr_private(&en, cs->data, cs->size);

    freeOfHash(&ofHash);
    freeCbuffer(&cs);

    return retCs;
}

OfSignVerfier initOfSignVerfier(RSA_PublicKey_ptr pubKey, HashType type)
{
    OfSignVerfier sv;
    sv._publicKey = pubKey;
    sv._type = type;

    return sv;
}

static int simple_test_str_equal(Cbuffer *str1, Cbuffer *str2)
{
    if (str1 == NULL || str2 == NULL)
        return -1;
    int len1 = str1->size;
    int len2 = str2->size;
    if (len1 != len2)
        return 0;

    for (int i = 0; i < len1; i++)
    {
        if (str1->data[i] != str2->data[i])
            return 0;
    }
    return 1;
}

int OfSignVerfierVerify(OfSignVerfier *verfier, const unsigned char *srcStr, int size, const Cbuffer *enHashStr)
{
    Decrypter de = initDecrypter(verfier->_publicKey);
    Cbuffer *deStr = getDecrptStr_public(&de, enHashStr->data, enHashStr->size);

    if (deStr == NULL)
        return -1;
    if (verfier == NULL)
        return -1;

    OfHash *ofHash = initOfHash((verfier->_type));
    if (ofHash == NULL)
    {
        freeCbuffer(&deStr);
        return -1;
    }

    if (updateOfHash(ofHash, srcStr, size) != 0)
    {
        freeCbuffer(&deStr);
        freeOfHash(&ofHash);
        return -1;
    }

    Cbuffer *hashRet = getHashOfHash(ofHash);

    int ret = !simple_test_str_equal(deStr, hashRet);

    freeCbuffer(&deStr);
    freeOfHash(&ofHash);
    freeCbuffer(&hashRet);

    return ret;
}
