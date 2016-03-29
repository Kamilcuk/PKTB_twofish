#ifndef SZYFROWANIE_HPP
#define SZYFROWANIE_HPP

#include "twofish.hpp"
#include <fstream>
#include <string>

class Szyfrowanie
{
    enum Tryb {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
    };
    Tryb tryb_;
    Twofish twofish;

public:
    Szyfrowanie(const unsigned char *_key = 0, int keylen = 0);
    void setKey(const unsigned char *_key, int keylen);
    void setTryb(Szyfrowanie::Tryb tryb);
    int setTryb(std::string tryb);

    void encrypt(std::istream &in, std::ostream &out);
    void decrypt(std::istream &in, std::ostream &out);
    void czytaj(std::istream &in, unsigned char plaintext[], int len);
};

#endif // SZYFROWANIE_HPP
