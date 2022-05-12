#ifndef OF_ASALGOTOOLS_H
#define OF_ASALGOTOOLS_H

#include "ofHash.h"

#include <string.h>



typedef char *RSA_keyPtr;

typedef enum pubKeyStoreType
{
    PkSType_PKCS1 = 0, // 老式 公钥格式
    PkSType_PKCS8 = 1
} PkSType;

typedef struct RSA_Key
{
    RSA_keyPtr _key;
} RSA_Key;

void freeRSA_Key(RSA_Key **);

typedef struct RSA_Key *RSA_PublicKey_ptr;
typedef struct RSA_Key *RSA_PrivateKey_ptr;

typedef struct RSA_Keys
{
    RSA_PublicKey_ptr publicKey;
    RSA_PrivateKey_ptr privateKey;
} RSA_Keys;

// 非对称算法密钥对生成 秘钥 存储 导入 转换
// pin 五位小数以内，比如12345,这个pin对后面加解密没什么用
// 即时pin相同每次生成的秘钥也是不一样的
// bit 必须是1024整数倍，bit越大加密效果越好，秘钥生成\加解密时间都增加
// 注意的是一次最多加密string 大小是(keybit/8)-7,
// 比如生成的keys用的是1024位那么一次最多一次加密(1024/8)-7=121个字符
RSA_Keys generateKeys(int pin, int bit);
int storePublicKeyTofile(const char *file, RSA_PublicKey_ptr publicKey, PkSType type);
int storePrivateKeyTofile(const char *file, RSA_PrivateKey_ptr privateKey);
RSA_PublicKey_ptr readPublicKeyFromfile(const char *file);
RSA_PrivateKey_ptr readPrivateKeyFromfile(const char *file);

Cbuffer *publicKeyTostr(RSA_PublicKey_ptr publicKey, PkSType type);
RSA_PublicKey_ptr strToPublicKey(const char *pubKey);
Cbuffer *privateKeyTostr(RSA_PrivateKey_ptr privateKey);
RSA_PrivateKey_ptr strToPrivateKey(const char *priKey);

// 非对称算法加密器
typedef struct Encrypter
{
    RSA_PublicKey_ptr _publicKey;
} Encrypter;
Encrypter initEncrypter(RSA_PublicKey_ptr pubKey);
// 注意的是一次最多加密string 大小是(keybit/8)-7,
// 比如生成的keys用的是1024位那么最多一次加密(1024/8)-7=121个字符
Cbuffer *encrptStr(const Encrypter *en, const Cbuffer *srcStr);

// 非对称算法解密器
typedef struct Decrypter
{
    RSA_PrivateKey_ptr _privateKey;
} Decrypter;
Decrypter initDecrypter(RSA_PrivateKey_ptr priKey);
Cbuffer *getDecrptStr(const Decrypter *de, const Cbuffer *input);

// 签名器
// 注意: 秘钥如果位数1024 不能使用HashType::Sha512 签名的，如果要用sha512
// 那么秘钥位数用2048
typedef struct OfSigner
{
    RSA_PrivateKey_ptr _privateKey;
    HashType _type;
} OfSigner;
// 要求必须传递私钥
// 注意: 秘钥如果位数1024 不能使用HashType::Sha512 签名的，如果要用sha512 那么秘钥位数用2048以上
OfSigner initOfSigner(const RSA_PrivateKey_ptr priKey, HashType type);
Cbuffer *getSignStr(const OfSigner *siger, const Cbuffer *srcStr);

// 签名验证器
typedef struct OfSignVerfier
{

    RSA_PublicKey_ptr _publicKey;
    HashType _type;
} OfSignVerfier;
// 要求必须传递公钥
OfSignVerfier initOfSignVerfier(RSA_PublicKey_ptr pubKey, HashType type);
// 返回0 表示验证成功
int OfSignVerfierVerify(OfSignVerfier *verfier, const unsigned char*srcStr,int size, const Cbuffer *enHashStr);

#endif