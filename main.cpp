#include <iostream>
#include<iomanip>
#include "aes.h"

using namespace std;

void printState(const uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            cout << "0x" << setw(2) << setfill('0') << hex << (int)state[i][j] << " ";
        }
        cout << endl;
    }
    cout << endl;
}

int main() {
    uint8_t in[16]  = { 0x32, 0x43, 0xf6, 0xa8, 0x88,
                        0x5a, 0x30, 0x8d, 0x31, 0x31,
                        0x98, 0xa2, 0xe0, 0x37, 0x07,
                        0x34 };

    uint8_t out[16] = { 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00 };

    uint8_t key[16] =  { 0x2b, 0x7e, 0x15, 0x16, 0x28,
                         0xae, 0xd2, 0xa6, 0xab, 0xf7,
                         0x15, 0x88,0x09, 0xcf, 0x4f,
                         0x3c };

    uint8_t state[4][4] =  { {0x19,0xa0,0x9a,0xe9},
                             {0x3d,0xf4,0xc6,0xf8},
                             {0xe3,0xe2,0x8d,0x48},
                             {0xbe,0x2b,0x2a,0x08}};

    AES* aesencryption = new AES();

    cout << "Original State For Test" << endl;
    printState(state);

    cout << "Checking KeyExpansion Routine" << endl;
    uint32_t* w = aesencryption->KeyExpansion(key, 4, 10);
    for (int i = 0; i < 44; i++) {
        cout << "0x" << setw(8) << setfill('0') << hex << w[i] << " ";
        if ((i + 1) % 4 == 0) {
            cout << endl;
        }
    }
    cout << endl;

    cout << "Checking SubBytes Method" << endl;
    aesencryption->subBytes(state);
    // check that state == sub
    printState(state);

    cout << "Checking ShiftRows Method" << endl;
    aesencryption->shiftRows(state);
    // check that state == shift
    printState(state);

    cout << "Checking MixColumns Method" << endl;
    aesencryption->mixColumns(state);
    printState(state);

    cout << "Checking AddRoundKey Method" << endl;
    aesencryption->addRoundKey(state, w, 1);
    printState(state);

    cout << "Checking the Cipher Routing" << endl;
    aesencryption->cipher(in, out, w);
    for (int j = 0; j < 16; j++) {
        cout << "0x" << setw(2) << setfill('0') << hex << (int)out[j] << " ";
    }
    cout << endl;

    /*
            cipher input
            start:
            state at start of round[r]
            s_box:
            state after SubBytes()
            s_row:
            state after ShiftRows()
            m_col:
            state after MixColumns()
            k_sch:
            key schedule value for round[r]
            output:
            cipher output
     */

    return 0;
}
