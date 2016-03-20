#include "twofishtest.hpp"
#include "twofish.hpp"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

/**
  Performs a self-test of the Twofish block cipher
*/
int twofish_test1(void)
{
 static const struct {
     int keylen;
     unsigned char key[32], pt[16], ct[16];
 } tests[] = {
   { 16,
     { 0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
       0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A },
     { 0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
       0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19 },
     { 0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
       0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3 }
   }, {
     24,
     { 0x88, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36,
       0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88,
       0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44 },
     { 0x39, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5,
       0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2 },
     { 0x18, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45,
       0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65 }
   }, {
     32,
     { 0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
       0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
       0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
       0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F },
     { 0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
       0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6 },
     { 0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
       0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA }
   }
};


 Twofish twofish;
 unsigned char tmp[2][16];
 int i, y;

 for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
    twofish.key_setup(tests[i].key, tests[i].keylen);
    twofish.encrypt(tests[i].pt, tmp[0]);
    twofish.decrypt(tmp[0], tmp[1]);
    if (memcmp(tmp[0], tests[i].ct, 16) != 0 || memcmp(tmp[1], tests[i].pt, 16) != 0) {
       return -1;
    }
      /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
      for (y = 0; y < 16; y++) tmp[0][y] = 0;
      for (y = 0; y < 1000; y++) twofish.encrypt(tmp[0], tmp[0]);
      for (y = 0; y < 1000; y++) twofish.decrypt(tmp[0], tmp[0]);
      for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return -2;
 }
 return 0;
}


#define Twofish_fatal(str) do { std::cout << __FUNCTION__ << " " << __LINE__ << " " << str << std::endl; exit(-1); }while(0)

/*
 * Perform a single self test on a (plaintext,ciphertext,key) triple.
 * Arguments:
 *  key     array of key bytes
 *  key_len length of key in bytes
 *  p       plaintext
 *  c       ciphertext
 */
void test_vector(unsigned char key[], int key_len, unsigned char p[16],
         unsigned char c[16])
{
    unsigned char tmp[16];	/* scratch pad. */
    int i;

    /* Prepare the key */
    Twofish twofish(key, key_len);

    /*
     * We run the test twice to ensure that the xkey structure
     * is not damaged by the first encryption.
     * Those are hideous bugs to find if you get them in an application.
     */
    for (i = 0; i < 2; i++) {
        /* Encrypt and test */
        twofish.encrypt(p, tmp);
        if (memcmp(c, tmp, 16) != 0) {
            Twofish_fatal("Twofish encryption failure");
        }

        /* twofish_decrypt and test */
        twofish.decrypt(c, tmp);
        if (memcmp(p, tmp, 16) != 0) {
            Twofish_fatal("Twofish twofish_decryption failure");
        }
    }

    /* The test keys are not secret, so we don't need to wipe xkey. */
}

/*
 * Check implementation using three (key,plaintext,ciphertext)
 * test vectors, one for each major key length.
 *
 * This is an absolutely minimal self-test.
 * This routine does not test odd-sized keys.
 */
void test_vectors()
{
    /*
     * We run three tests, one for each major key length.
     * These test vectors come from the Twofish specification.
     * One encryption and one twofish_decryption using randomish data and key
     * will detect almost any error, especially since we generate the
     * tables ourselves, so we don't have the problem of a single
     * damaged table entry in the source.
     */

    /* 128-bit test is the I=3 case of section B.2 of the Twofish book. */
    static unsigned char k128[] = {
        0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
        0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
    };
    static unsigned char p128[] = {
        0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
        0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
    };
    static unsigned char c128[] = {
        0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
        0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
    };

    /* 192-bit test is the I=4 case of section B.2 of the Twofish book. */
    static unsigned char k192[] = {
        0x88, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36,
        0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88,
        0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44
    };
    static unsigned char p192[] = {
        0x39, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5,
        0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2
    };
    static unsigned char c192[] = {
        0x18, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45,
        0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65
    };

    /* 256-bit test is the I=4 case of section B.2 of the Twofish book. */
    static unsigned char k256[] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };
    static unsigned char p256[] = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
    };
    static unsigned char c256[] = {
        0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
        0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
    };

    /* Run the actual tests. */
    test_vector(k128, 16, p128, c128);
    test_vector(k192, 24, p192, c192);
    test_vector(k256, 32, p256, c256);
}

/*
 * Perform extensive test for a single key size.
 *
 * Test a single key size against the test vectors from section
 * B.2 in the Twofish book. This is a sequence of 49 encryptions
 * and twofish_decryptions. Each plaintext is equal to the ciphertext of
 * the previous encryption. The key is made up from the ciphertext
 * two and three encryptions ago. Both plaintext and key start
 * at the zero value.
 * We should have designed a cleaner recurrence relation for
 * these tests, but it is too late for that now. At least we learned
 * how to do it better next time.
 * For details see appendix B of the book.
 *
 * Arguments:
 * key_len      Number of bytes of key
 * final_value  Final plaintext value after 49 iterations
 */
void test_sequence(int key_len, unsigned char final_value[])
{
    unsigned char buf[(50 + 3) * 16];	/* Buffer to hold our computation values. */
    unsigned char tmp[16];	/* Temp for testing the twofish_decryption. */
    int i;
    unsigned char *p;

    /* Wipe the buffer */
    memset(buf, 0, sizeof(buf));

    /*
     * Because the recurrence relation is done in an inconvenient manner
     * we end up looping backwards over the buffer.
     */

    /* Pointer in buffer points to current plaintext. */
    p = &buf[50 * 16];
    for (i = 1; i < 50; i++) {
        /*
         * Prepare a key.
         * This automatically checks that key_len is valid.
         */
        Twofish twofish(p + 16, key_len);

        /* Compute the next 16 bytes in the buffer */
        twofish.encrypt(p, p - 16);

        /* Check that the twofish_decryption is correct. */
        twofish.decrypt(p - 16, tmp);
        if (memcmp(tmp, p, 16) != 0) {
            Twofish_fatal
                ("Twofish twofish_decryption failure in sequence");
        }
        /* Move on to next 16 bytes in the buffer. */
        p -= 16;
    }

    /* And check the final value. */
    if (memcmp(p, final_value, 16) != 0) {
        Twofish_fatal("Twofish encryption failure in sequence");
    }

    /* None of the data was secret, so there is no need to wipe anything. */
}

/*
 * Run all three sequence tests from the Twofish test vectors.
 *
 * This checks the most extensive test vectors currently available
 * for Twofish. The data is from the Twofish book, appendix B.2.
 */
void test_sequences()
{
    static unsigned char r128[] = {
        0x5D, 0x9D, 0x4E, 0xEF, 0xFA, 0x91, 0x51, 0x57,
        0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0
    };
    static unsigned char r192[] = {
        0xE7, 0x54, 0x49, 0x21, 0x2B, 0xEE, 0xF9, 0xF4,
        0xA3, 0x90, 0xBD, 0x86, 0x0A, 0x64, 0x09, 0x41
    };
    static unsigned char r256[] = {
        0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75,
        0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05
    };

    /* Run the three sequence test vectors */
    test_sequence(16, r128);
    test_sequence(24, r192);
    test_sequence(32, r256);
}

int TwofishTest::runTests()
{
    twofish_test1();
    test_sequences();
    test_vectors();
    return 0;
}
