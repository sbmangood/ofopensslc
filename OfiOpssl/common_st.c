#include "common_st.h"
#include <malloc.h>
#include <string.h>

Cbuffer *initCbuffer()
{
    Cbuffer *cs= (Cbuffer *)malloc(sizeof(Cbuffer));
    cs->data=NULL;
    cs->size=0;

    return cs;
}

Cbuffer *initCbuffeWithData(const unsigned char *data,int size)
{
    Cbuffer *cs= (Cbuffer *)malloc(sizeof(Cbuffer));
    cs->data=(unsigned char *)malloc((size_t)size);
    memcpy(cs->data,data,(size_t)size);
    cs->size=size;

    return cs;
}
void freeCbuffer(Cbuffer **cstr)
{
    if(cstr==NULL || *cstr==NULL)
        return;
    
    if((*cstr)->data!=NULL)
        free((*cstr)->data);
    
    (*cstr)->data=NULL;
    
    free(*cstr);

    *cstr=NULL;
}

void *mallocAndSetZero(int size)
{
    void *buf=(void *)malloc((size_t)size);
    memset(buf,0,(size_t)size);
    return buf;
}