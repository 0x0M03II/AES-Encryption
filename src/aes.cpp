#include "aes.h"
#include <iostream>

using namespace aes583;

inline uint8_t AES::ffAdd(uint8_t input, uint8_t input2)
{
    uint8_t newValue;
    newValue = input ^ input2;

    return newValue;
}

inline uint8_t AES::xtime(uint8_t polyn) {
    /*
     * * * * * * FIPS pg. 11 * * * * *
     *  Multiplication by x can be implemented
     *  at the byte level as a left shift and a
     *  subsequent conditional bitwise XOR with
     *  {1b}
    */

    uint8_t newValue = polyn << 1;

    if (polyn & 0x80) {
        newValue ^= 0x1b;
    }

    // print return value using static_cast<>()
    return newValue;
}

inline uint8_t AES::ffMultiply(uint8_t num1, uint8_t num2) {

    /*
     * Using the Fast multiplication table algorithm from
     * our lecture and the FIPS doc, we must use our xtime
     * function to left shift and apply the AES irreducible
     * polynomial mod our polynomial to keep the size
     * less than or equal to degree 7.
     *
     * This is done for every bit in our polynomial.  If the bit
     * is 1, we add our new constant value returned by xtime()
     * to sum by XORing.
     */
    uint8_t sum = 0;
    uint8_t res = num2;

    // for every bit in num1
    for (int i = 0; i < 8; i++) {
        // mask current bit to determine if set
        if (num1 & 0x01) {
            // xor our sum with xtime() return constant
            sum ^= res;
        }

        // Get new constant
        res = xtime(res);
        num1 >>= 1; // move to the next bit
    }

    return sum;
}


void AES::subBytes(int (&state)[4][4])
{
    uint8_t a, b;
    int subValue = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // get x/y coordinates from j
            subValue = state[i][j];

            a = (subValue >> 4);
            // bit mask 15 for low order 4 bits
            b = (subValue & 0x0f);

            subValue = sbox[a][b];
            state[i][j] = subValue;
        }
    }
}

//void AES::rotWord(word_t* rWord)
//{
//    uint8_t swap = rWord->word[0];
//    for (int i = 0; i <= 2; i++) {
//        rWord->word[i] = rWord->word[i + 1];
//    }
//    rWord->word[3] = swap;
//}

uint32_t AES::rotWord(uint32_t rWord)
{
    uint8_t swap = ((rWord >> 24) & 0xFF);
    rWord <<= 8;
    rWord |= swap;

    return rWord;
}

uint32_t AES::subWord(uint32_t sWord)
{
    for (int i = 3; i >= 0; i--) {
        uint8_t sValue = ((sWord >> (i * 8)) & 0xFF);

        uint8_t a = (sValue >> 4);
        uint8_t b = (sValue & 0x0f);

        uint8_t transWord = sbox[a][b];

        sWord &= ~(0xFF << (i * 8));

        sWord |= (static_cast<uint32_t>(transWord) << (i * 8));
    }

    return sWord;
}

uint32_t AES::aesWord(uint8_t key0, uint8_t key1, uint8_t key2, uint8_t key3)
{
    return (static_cast<uint32_t>(key0) << 24) |
           (static_cast<uint32_t>(key1) << 16) |
           (static_cast<uint32_t>(key2) << 8) |
           key3;
}


uint32_t* AES::KeyExpansion(uint8_t* key, int Nk, int Nr)
{
    /*
     * FIPS Key Expansion algorithm on page 19 The first Nk
     * words of the expanded key are filled with the cipher key.
     *
     * Every word w[i] is equal to the XOR of w[i - 1] and
     * the word Nk positions earlier (w[i - Nk]).  If a word
     * is a multiple of Nk, the following transformation is
     * applied to w[i - 1]:
     *
     * * * * * * * * * * Transformation * * * * * * * * *
     *
     * 1. rotWord(w[i - 1])
     * 2. subWord(w[i - 1])
     * 3. w[i - 1] ^= Rcon[i - 1, 0x00, 0x00, 0x00]
     * 4. w[i - 1] ^= w[i - Nk]
     *
     *
     */


    int maxWords = 4 * (Nr + 1);
    int i = 0;
    auto w = new uint32_t[maxWords];

    while (i < Nk) {
        w[i] = aesWord(
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3]
        );
        i++;
    }

    i = Nk;

    /* starting at Nk because the first Nk are filled */
    while (i < maxWords) {
        uint32_t previousWord = w[i - 1];

        if (i % Nk == 0) {
            previousWord = rotWord(previousWord);
            previousWord = subWord(previousWord);

            // Rcon values are 32-bit so shift to get first byte
            previousWord ^= (Rcon[i / Nk] << 24);

        } else if (Nk > 6 && i % Nk == 4) {
            previousWord = subWord(previousWord);
        }

        // continue with original XOR
        w[i] = w[i - Nk] ^ previousWord;
        i++;
    }

    return w;
}
