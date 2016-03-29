#include "szyfrowanie.hpp"
#include <iostream>
#include <cstring>
#include <ctime>
#include <cstdlib>

Szyfrowanie::Szyfrowanie(const unsigned char *_key, int keylen) :
    tryb_(ECB),
    twofish(_key, keylen)
{
    srand(time(NULL));
}

void Szyfrowanie::setKey(const unsigned char *_key, int keylen)
{
    twofish.key_setup(_key, keylen);
}

void Szyfrowanie::setTryb(Szyfrowanie::Tryb tryb)
{
    tryb_ = tryb;
}

int Szyfrowanie::setTryb(std::string tryb)
{
    int ret = 0;
    if ( tryb == "ECB" )
        setTryb(ECB);
    else if ( tryb == "CBC" )
        setTryb(CBC);
    else if ( tryb == "PCBC" )
        setTryb(PCBC);
    else if ( tryb == "CFB" )
        setTryb(CFB);
    else if ( tryb == "OFB" )
        setTryb(OFB);
    else
        ret = -1;
    return ret;
}

void memxor(unsigned char *a, unsigned char *b, const int len)
{
    for(int i=0;i<len;++i)
        a[i]^=b[i];
}
void memxor(unsigned char *a,unsigned char *b,unsigned char *c, const int len)
{
    for(int i=0;i<len;++i)
        a[i]=b[i]^c[i];
}
void memrand(unsigned char *a,const int len)
{
    for(int i=0;i<len;++i)
        a[i]=rand()&0xff;
}

void Szyfrowanie::czytaj(std::istream &in, unsigned char plaintext[], int len) {
    /* funckja czyta i parsuje do długości bloku (16 bajtów) */
    in.read((char *)plaintext, 16);
    len = in.gcount();
    if ( len < 16 ) {
        memset(&plaintext[len-1], 0, 16-len+1);
    }
}

void Szyfrowanie::encrypt(std::istream &in, std::ostream &out)
{
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
    unsigned char vector[16];
    unsigned char buff[16];
    switch(tryb_) {
    case ECB:
        while( in ) {
            czytaj(in, plaintext, 16);
            twofish.encrypt(plaintext, ciphertext);
            out.write((char*)ciphertext,16);
        }
        break;
    case CBC:
        /* generate and write init vector */
        memrand(vector,16);
        out.write((char*)vector,16);

        while( in ) {
            czytaj(in, plaintext, 16);
            /* xor with vector */
            memxor(plaintext, vector, 16);
            twofish.encrypt(plaintext, ciphertext);
            out.write((char*)ciphertext,16);
            /* next vector is output text */
            memcpy(vector, ciphertext, 16);
        }
        break;
    case PCBC:
        /* generate and write init vector */
        memrand(vector,16);
        out.write((char*)vector,16);

        while( in ) {
            czytaj(in, plaintext, 16);
            /* xor with vector */
            memxor(buff, plaintext, vector, 16);
            twofish.encrypt(buff, ciphertext);
            out.write((char*)ciphertext,16);
            /* next vector */
            memxor(vector, plaintext, ciphertext, 16);
        }
        break;
    case CFB:
        /* generate and write init vector */
        memrand(vector,16);
        out.write((char*)vector,16);

        while( in ) {
            twofish.encrypt(vector, buff);

            czytaj(in, plaintext, 16);
            memxor(ciphertext, buff, plaintext, 16);

            out.write((char *)ciphertext,16);
            memcpy(vector, ciphertext, 16);
        }
        break;
    case OFB:
        /* generate and write init vector */
        memrand(vector,16);
        out.write((char*)vector,16);

        while( in ) {
            twofish.encrypt(vector, buff);

            czytaj(in, plaintext, 16);
            memxor(ciphertext, buff, plaintext, 16);
            out.write((char *)ciphertext,16);

            memcpy(vector, buff, 16);
        }
        break;
    default:
        break;
    }
}

#include <stdio.h>
void Szyfrowanie::decrypt(std::istream &in, std::ostream &out)
{
    unsigned char ciphertext[16];
    unsigned char plaintext[16];
    unsigned char vector[16];
    unsigned char buff[16];
    int len = 0;
    switch(tryb_) {
    case ECB:
        while( in ) {
            in.read((char*)ciphertext,16);
            if ( !in ) break;
            len = in.gcount();
            if ( len < 16 ) {
                memset(&ciphertext[len+1], 0, 16-len);
            }
            twofish.decrypt(ciphertext, plaintext);
            out.write((char*)plaintext,len);
        }
        break;
    case CBC:
        /* first is init vector */
        in.read((char*)vector,16);

        while( in ) {
            in.read((char *)ciphertext,16);
            if ( !in ) break;
            len = in.gcount();
            if ( len < 16 ) {
                memset(&ciphertext[len+1], 0, 16-len);
            }
            twofish.decrypt(ciphertext, plaintext);
            memxor(plaintext, vector, 16);
            out.write((char*)plaintext,16);
            /* next vetor */
            memcpy(vector, ciphertext, len);
        }
        break;
    case PCBC:
        /* first is init vector */
        in.read((char*)vector,16);

        while( in ) {
            in.read((char *)ciphertext,16);
            if ( !in ) break;
            twofish.decrypt(ciphertext, plaintext);
            /* xor with vector */
            memxor(buff, plaintext, vector, 16);
            out.write((char*)buff,16);
            /* next vector */
            memxor(vector, ciphertext, buff, 16);
        }
        break;
    case CFB:
        /* first is init vector */
        in.read((char*)vector,16);

        while( in ) {
            twofish.encrypt(vector, buff);

            in.read((char *)ciphertext,16);
            if ( !in ) break;
            /* xor with vector */
            memxor(plaintext, buff, ciphertext, 16);
            out.write((char *)plaintext,16);
            /* next vector */
            memcpy(vector, ciphertext, 16);
        }
        break;
    case OFB:
        /* first is init vector */
        in.read((char*)vector,16);

        while( in ) {
            twofish.encrypt(vector, buff);

            in.read((char *)ciphertext,16).eof();
            if ( !in ) break;
            /* xor with vector */
            memxor(plaintext, buff, ciphertext, 16);
            out.write((char *)plaintext,16);
            /* next vector */
            memcpy(vector, buff, 16);
        }
        break;
    default:
        break;
    }
}
