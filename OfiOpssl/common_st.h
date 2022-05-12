#pragma once

typedef struct Cbuffer
{
    unsigned char *data;
    int size;
}Cbuffer;

Cbuffer *initCbuffer();
Cbuffer *initCbuffeWithData(const unsigned char *data,int size);
void freeCbuffer(Cbuffer **cstr);

void *mallocAndSetZero(int size);
