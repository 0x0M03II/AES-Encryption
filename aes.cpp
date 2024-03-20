#include "aes.h"
#include <iostream>


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


void AES::subBytes(uint8_t (&state)[4][4])
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

void AES::invSubBytes(uint8_t (&state)[4][4])
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

            subValue = InvSbox[a][b];
            state[i][j] = subValue;
        }
    }
}

void AES::shiftRows(uint8_t (&state)[4][4])
{
    /*
     *
     * * * * * * * ShiftRows * * * * * *
     * ShiftRows as defined in the FIPS documentation skips the
     * first row and, for every subsequent row, that row is shifted
     * r times.
     *
     * This implementation shifts each column while looping; for example
     * column 0 / row 1 in the new array becomes the value at
     * state[1][1].  This is because (c+r) = (0+1).
     */

    uint8_t temp[4];

    for (int r = 1; r < 4; r++) {

        for (int c = 0; c < 4; c++) {
            temp[c] = state[r][(c + r) % 4];
        }

        // assignment into state
        for (int c = 0; c < 4; c++)  {
            state[r][c] = temp[c];
        }
    }
}

//void AES::invShiftRows(uint8_t (&state)[4][4])
//{
//    uint8_t temp;
//
//    // Loop through each row, starting from the second row
//    for (int row = 1; row < 4; ++row) {
//        for (int shifts = 0; shifts < row; ++shifts) {
//            // Perform the shift to the right
//            temp = state[row][3];
//            for (int col = 3; col > 0; --col) {
//                state[row][col] = state[row][col - 1];
//            }
//            state[row][0] = temp;
//        }
//    }
//}

void AES::invShiftRows(uint8_t (&state)[4][4]) {
    uint8_t temp;

    // Row 1: Shift 1 position to the right
    temp = state[1][3];
    for (int col = 3; col > 0; --col) {
        state[1][col] = state[1][col - 1];
    }
    state[1][0] = temp;

    // Row 2: Shift 2 positions to the right
    // Do it twice
    for (int shifts = 0; shifts < 2; ++shifts) {
        temp = state[2][3];
        for (int col = 3; col > 0; --col) {
            state[2][col] = state[2][col - 1];
        }
        state[2][0] = temp;
    }

    // Row 3: Shift 3 positions to the right
    // Do it three times
    for (int shifts = 0; shifts < 3; ++shifts) {
        temp = state[3][3];
        for (int col = 3; col > 0; --col) {
            state[3][col] = state[3][col - 1];
        }
        state[3][0] = temp;
    }
}

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


void AES::mixColumns(uint8_t (&state)[4][4])
{
    uint8_t temp[8];

    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            temp[row] =
                    ffMultiply(state[0][col], MixColumsMatrics[row][0]) ^
                    ffMultiply(state[1][col], MixColumsMatrics[row][1]) ^
                    ffMultiply(state[2][col], MixColumsMatrics[row][2]) ^
                    ffMultiply(state[3][col], MixColumsMatrics[row][3]);
        }

        for (int row = 0; row < 4; ++row) {
            state[row][col] = temp[row];
        }
    }
}

void AES::invMixColumns(uint8_t (&state)[4][4])
{
    uint8_t temp[8];

    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            temp[row] =
                    ffMultiply(state[0][col], InvMixColumsMatrics[row][0]) ^
                    ffMultiply(state[1][col], InvMixColumsMatrics[row][1]) ^
                    ffMultiply(state[2][col], InvMixColumsMatrics[row][2]) ^
                    ffMultiply(state[3][col], InvMixColumsMatrics[row][3]);
        }

        for (int row = 0; row < 4; ++row) {
            state[row][col] = temp[row];
        }
    }
}

void AES::addRoundKey(uint8_t (&state)[4][4], uint32_t* w, int round)
{
    int start = round * 4;

    for (int i = 0; i < 4; i++) {
        uint32_t roundKeyWord = w[start + i];

        for (int j = 0; j < 4; j++) {
            // determine which round key we need
            uint8_t roundKeyByte = (roundKeyWord >> (24 - 8 * j)) & 0xFF;
            state[j][i] ^= roundKeyByte;
        }
    }
}

void AES::cipher(uint8_t in[16], uint8_t (&out)[16], uint32_t* w, int Nr)
{
    int round = 0;
    uint8_t state[4][4];
    for (int k = 0; k < 16; k++) {
        state[k % 4][k / 4] = in[k];
    }

    printf("round[%2d].input     %s\n", round, plaintext);
    printf("round[%2d].k_sch     %s\n", round, printRoundKey(w, round).c_str());
    addRoundKey(state, w, 0);

    for (round = 1; round < Nr; round++) {
        printf("round[%2d].start     %s\n", round, printHexString(state).c_str());

        subBytes(state);
        printf("round[%2d].s_box     %s\n", round, printHexString(state).c_str());

        shiftRows(state);
        printf("round[%2d].s_row     %s\n", round, printHexString(state).c_str());

        mixColumns(state);
        printf("round[%2d].m_col     %s\n", round, printHexString(state).c_str());

        addRoundKey(state, w, round);
        printf("round[%2d].k_sch     %s\n", round, printRoundKey(w, round).c_str());
    }

    // final round
    printf("round[%2d].start     %s\n", round, printHexString(state).c_str());

    subBytes(state);
    printf("round[%2d].s_box     %s\n", round, printHexString(state).c_str());

    shiftRows(state);
    printf("round[%2d].s_row     %s\n", round, printHexString(state).c_str());

    addRoundKey(state, w, Nr);
    printf("round[%2d].k_sch     %s\n", round, printRoundKey(w, round).c_str());

    printf("round[%2d].output    %s\n", round, printHexString(state).c_str());

    // save to out for use by invCipher
    int i = 0;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            out[i++] = state[row][col];
        }
    }
}

void AES::invCipher(uint8_t in[16], uint8_t out[16], uint32_t* w, int Nr)
{
    int round = 0;
    int invRound = 1;
    uint8_t state[4][4];
    for (int k = 0; k < 16; k++) {
        state[k % 4][k / 4] = in[k];
    }

    printf("round[%2d].iinput    %s\n", round, plaintext);
    printf("round[%2d].ik_sch    %s\n", round, printRoundKey(w, Nr).c_str());
    addRoundKey(state, w, Nr);

    for (round = Nr - 1; round > 0; round--) {
        printf("round[%2d].istart    %s\n", invRound, printHexString(state).c_str());

        invShiftRows(state);
        printf("round[%2d].is_row    %s\n", invRound, printHexString(state).c_str());

        invSubBytes(state);
        printf("round[%2d].is_box    %s\n", invRound, printHexString(state).c_str());

        printf("round[%2d].ik_sch    %s\n", invRound, printRoundKey(w, round).c_str());

        addRoundKey(state, w, round);
        printf("round[%2d].ik_add    %s\n", invRound, printHexString(state).c_str());

        invMixColumns(state);
        invRound++;
    }

	printf("round[%2d].istart    %s\n", invRound, printHexString(state).c_str());

    invShiftRows(state);
    printf("round[%2d].is_row    %s\n", invRound, printHexString(state).c_str());

    invSubBytes(state);
    printf("round[%2d].is_box    %s\n", invRound, printHexString(state).c_str());

    addRoundKey(state, w, 0);
    printf("round[%2d].ik_sch    %s\n", invRound, printRoundKey(w, 0).c_str());

    printf("round[%2d].ioutput   %s\n", invRound, printHexString(state).c_str());

}

/* Implement AES Encryption */
std::string AES::printHexString(const uint8_t state[4][4]) const {
    std::ostringstream oss;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(state[row][col]);
        }
    }
    return oss.str();
}

std::string AES::printRoundKey(const uint32_t* w, int round) const {
    std::ostringstream oss;

    int startIndex = round * 4;
    for (int i = 0; i < 4; i++) {
        oss << std::hex << std::setfill('0') << std::setw(8) << w[startIndex + i];
    }
    return oss.str();
}

void AES::updatePlaintext(char* pl) {

    plaintext = pl;
}