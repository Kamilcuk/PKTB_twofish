#ifndef TWOFISH_HPP
#define TWOFISH_HPP


typedef unsigned long ulong32;

struct Twofish {
    struct Key {
        unsigned char start;
        ulong32 K[40];
        unsigned char S[4][256];
    };
    Key key;
    Key *skey;
public:
    Twofish(const unsigned char *_key = 0, int keylen = 0);
    void key_setup(const unsigned char *_key, int keylen);
    void encrypt(const unsigned char *pt, unsigned char *ct);
    void decrypt(const unsigned char *pt, unsigned char *ct);
};

#endif // TWOFISH_HPP
