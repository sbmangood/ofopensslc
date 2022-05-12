#ifndef OF_AES_TOOLS_H_
#define OF_AES_TOOLS_H_

#include "common_st.h"


typedef struct Of_AES_key
{
    unsigned char * _key;
    int size;
}Of_AES_key;

// 正常要求key 长度是 16 24 32 字节之一，不够补偿固定字符'*'
Of_AES_key* initOf_AES_key(unsigned char *,int size);
void freeOf_AES_key(Of_AES_key ** key);


Cbuffer* AES_EncrypterEncryptStr(const Of_AES_key *aes_key,const unsigned char *input ,int size);

Cbuffer* AES_DecrypterDecryptStr(const Of_AES_key *aes_key,const unsigned char *input ,int size);

#endif