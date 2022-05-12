#include "test.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <string.h>
#include "OfiOpssl/ofAsAlgoTools.h"
#include "OfiOpssl/ofAES_Tools.h"

// just for test
static int simple_test_str_equal(Cbuffer *str1, Cbuffer *str2)
{
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

typedef struct SimpeStr
{
    int cp;
    int size;
    char *data;
} SimpeStr;

SimpeStr *initSimpeStr()
{
    SimpeStr *ss = (SimpeStr *)mallocAndSetZero(sizeof(SimpeStr));
    char *buf = (char *)mallocAndSetZero(1024);
    ss->data=buf;
    ss->cp = 1024;
    ss->size = 0;

    return ss;
}

void simpeStrAppend(SimpeStr **ss,const char*adstr,size_t size)
{
    if(ss==NULL)
        return;
    if(*ss==NULL)
        *ss=initSimpeStr();
    
    SimpeStr * tss=*ss;

    int f=tss->cp-tss->size-1;

    if(f<(int)size)
    {
        char *buf = (char *)mallocAndSetZero((*ss)->cp+(int)size-f);
        memcpy(buf, (*ss)->data, (size_t)((*ss)->size + 1));

        if ((*ss)->data != NULL)
            free((*ss)->data);

        (*ss)->data = buf;
        (*ss)->cp = (*ss)->cp+(int)size-f;
    }

    tss=*ss;



    memcpy(tss->data+tss->size,(void *)adstr,size);

    tss->size=tss->size+(int)size;

}


void freeSimpeStr(SimpeStr **ss)
{
    if (*ss == NULL)
        return;

    if ((*ss)->data != NULL)
        free((*ss)->data);
    (*ss)->data = NULL;
    free(*ss);
    *ss = NULL;
}
void pushSimpeStr(SimpeStr **ss, char ch)
{
    if(ss==NULL || *ss==NULL)
        return;
    if ((*ss)->cp == (*ss)->size + 1)
    {

        char *buf = (char *)mallocAndSetZero((*ss)->cp * 2);
        memcpy(buf, (*ss)->data, (size_t)((*ss)->size + 1));

        if ((*ss)->data != NULL)
            free((*ss)->data);

        (*ss)->data = buf;
        (*ss)->cp = (*ss)->cp * 2;
    }
    (*ss)->data[(*ss)->size] = ch;
    (*ss)->size = (*ss)->size + 1;
}


void free_str(char **str)
{
    if (*str != NULL)
        free(*str);
    *str = NULL;
}
// 测试哈希算法
void testOfHash(int times)
{
    for (int i = 0; i < times; i++)
    {
        for (int j = 0; j <= Sha512; j++)
        {
            Cbuffer *str1, *str2, *str3;

            str1 = str2 = str3 = NULL;

            struct OfHash *of = initOfHash((enum HashType)j);

            int ret = -1;
            ret = updateOfHash(of, (const unsigned char *)"ofilm", strlen("ofilm"));
            assert(ret == 0);
            ret = updateOfHash(of, (const unsigned char *)" openssl ", strlen(" openssl "));
            assert(ret == 0);
            ret = updateOfHash(of, (const unsigned char *)"work!", strlen("work!"));
            assert(ret == 0);

            str1 = getHashOfHash(of);

            freeOfHash(&of); // free(of) && of=NULL is not smart

            str2 = getHashStr((const unsigned char *)"ofilm openssl work!", strlen("ofilm openssl work!"), (enum HashType)(j));

            str3 = getFileHashStr("/ywh_work/data/srcs/OfilmOpssl/OfiOpssl/test/test.txt", (enum HashType)(j));

            printf("test string [ofilm openssl work!] hash\n");

            assert(str1 != NULL && str2 != NULL && str3 != NULL);
            printf("%s\n", str1->data);
            printf("%s\n", str2->data);
            printf("%s\n", str3->data);

            if (simple_test_str_equal(str1, str2) == 1 && simple_test_str_equal(str2, str3) == 1)
            {
                printf("str1==str2==str3 test ok\n");
            }

            const char *file = "/ywh_work/data/srcs/muduo/muduoSrc/install/lib/libmuduo_net.so";
            printf("Now test bigger file : %s\n", file);
            Cbuffer *str4 = NULL;
            str4 = getFileHashStr(file, (enum HashType)(j));
            assert(str4 != NULL);
            printf("Ret is %s\n", str4->data);

            // 链接库malloc 的内存,应该是链接库安全释放
            freeCbuffer(&str1);
            freeCbuffer(&str2);
            freeCbuffer(&str3);
            freeCbuffer(&str4);
        }
        printf("%d times\n", i + 1);
    }
    printf("\ntestAsAlgoTools over!\n\n\n");
}
// 测试非对称加密算法
void testAsAlgoTools()
{
    RSA_Keys keys = generateKeys(12345, 1024 * 2);

    const char *pubKeyPath = "./pubkey.pem";
    const char *priKeyPath = "./prikey.pem";

    int ret = storePublicKeyTofile(pubKeyPath, keys.publicKey, PkSType_PKCS8);
    assert(ret == 0);
    ret = storePrivateKeyTofile(priKeyPath, keys.privateKey);
    assert(ret == 0);
    // if no use key we free ,we will load key from file
    freeRSA_Key(&keys.publicKey);
    freeRSA_Key(&keys.privateKey);

    RSA_PrivateKey_ptr privateKey = readPrivateKeyFromfile(priKeyPath);
    assert(privateKey->_key != NULL);
    RSA_PublicKey_ptr publicKey = readPublicKeyFromfile(pubKeyPath);
    assert(publicKey->_key != NULL);

    // 加解密要求 公钥加密 私钥解密
    Encrypter encrypt = initEncrypter(publicKey);
    Decrypter decrypt = initDecrypter(privateKey);

    Cbuffer *srcStr = initCbuffeWithData((const unsigned char *)"what is a big joke!",
                            strlen("what is a big joke!"));
    printf("Source str: %s\n", (const char *)srcStr->data);

    Cbuffer *enstr = encrptStr(&encrypt, srcStr);
    //printf("encrypt ret: %s\n", enstr->data);
    

    Cbuffer *destr = getDecrptStr(&decrypt, enstr);
    assert(destr!=NULL);
    printf("decrypt ret: %s\n", (char *)destr->data);
    freeCbuffer(&enstr);
    freeCbuffer(&destr);

    SimpeStr *bigStr = initSimpeStr();
    for (int i = 0; i < 9999; i++)
    {
        pushSimpeStr(&bigStr, (char)('a' + i % 26));
        pushSimpeStr(&bigStr, (char)('A' + i % 26));
        pushSimpeStr(&bigStr, (char)('1' + i % 9));
    }
    Cbuffer *bigstrCb=initCbuffeWithData((unsigned char *)bigStr->data,bigStr->size);

    for (int i = Md5; i <= Sha512; i++)
    {
        // 签名和确认签名要求 私钥加密 公钥解密
        OfSigner signer = initOfSigner(privateKey, (HashType)(i));
        OfSignVerfier verfier = initOfSignVerfier(publicKey, (HashType)(i));

        Cbuffer *srcSign = getSignStr(&signer, bigstrCb);
        assert(srcSign!=NULL);
        //printf("srcSign = %s\n", srcSign->data);

        ret = OfSignVerfierVerify(&verfier, (const unsigned char *)bigStr->data, bigStr->size,srcSign);

        freeCbuffer(&srcSign);

        if (ret == 0)
            printf("verify ok!\n");
        else
            printf("verify wrong!\n");
    }
    freeSimpeStr(&bigStr);
    freeCbuffer(&bigstrCb);
    // test str-key key -str

    Cbuffer *pubkeyStr = publicKeyTostr(publicKey, PkSType_PKCS8);
    printf("publicKeyTostr %s\n", (char *)pubkeyStr->data);

    Cbuffer *prikeyStr = privateKeyTostr(privateKey);
    printf("privateKeyTostr %s\n", (char *)prikeyStr->data);

    RSA_PublicKey_ptr new_publicKey = strToPublicKey((const char *)pubkeyStr->data);
    RSA_PrivateKey_ptr new_privateKey = strToPrivateKey((const char *)prikeyStr->data);

    Encrypter new_encrypt = initEncrypter(new_publicKey);
    Decrypter new_decrypt = initDecrypter(new_privateKey);

    Cbuffer *new_enstr = encrptStr(&new_encrypt, srcStr);
    Cbuffer *new_destr = getDecrptStr(&new_decrypt, new_enstr);

    printf("new decrypt ret: %s\n", (char *)new_destr->data);

    // remember free... key Cbuffer.

    // ...
    printf("\ntestOfHash over!\n\n\n");
}

void testAesTools()
{
    const char* k = "eewegew3rerfdfwrewre3w";
    Of_AES_key *key=initOf_AES_key((unsigned char*)k,(int)strlen(k));
    
    SimpeStr *src = initSimpeStr();
    const char *tmp = "112$$$$3435a&&&&bddd6qqdE****ERERERE$**@@@)*!";
    for (int i = 0; i < 1000; i++){
        simpeStrAppend(&src,(const  char*)tmp,(size_t)(strlen(tmp)));
    }
    const char* tmp2 = "123456789112222222333erererer33333331234567891234567891234567891234568912345";
    simpeStrAppend(&src,(const  char*)tmp2,(size_t)(strlen(tmp2)));
    const char *tmp3= "123456789112222222333erererer33333331234567891234567t891234567891234568912345";
    simpeStrAppend(&src,(const  char*)tmp3,(size_t)(strlen(tmp3)));

    printf("Src str size = %d\n",src->size);
    
    Cbuffer* encryptStr = AES_EncrypterEncryptStr(key,(const unsigned char *)src->data,src->size);

    Cbuffer* decryptStr = AES_DecrypterDecryptStr(key,(const unsigned char *)encryptStr->data,encryptStr->size);
    printf("Decrypt str size =%d\n",decryptStr->size);
    printf("Decrypt ret is :%s\n",decryptStr->data);

    // remember free... key Cbuffer.

    // 错误用法，一次加密对应一次解密;两段或者几段加密文放在一起，不能一次解密
    // 解析加密的一部分也不能，每次加密后需要分段
    // 所以如果密文存文件，需要先存头部，比如一段密文的大小，这样解密时候就知道一段一段的解密

    printf("\ntestAesTools over!\n\n\n");
}

int main(int argc, char **argv)
{
    int n = 4;
    n++;

    testOfHash(n);
    testAsAlgoTools();
    testAesTools();
    return 0;
}