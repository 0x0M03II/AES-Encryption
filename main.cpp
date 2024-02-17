#include <iostream>
#include <iomanip>
#include <sstream>
#include "aes.h"

using namespace std;

/* Uncomment below for unit tests */

//void printState(const uint8_t state[4][4]) {
//    for (int i = 0; i < 4; i++) {
//        for (int j = 0; j < 4; j++) {
//            cout << "0x" << setw(2) << setfill('0') << hex << (int)state[i][j] << " ";
//        }
//        cout << endl;
//    }
//    cout << endl;
//}

void hexStringToUint8Key(const std::string &hexStr, uint8_t key[16]) {
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        std::istringstream iss(hexStr.substr(i * 2, 2));
        iss >> std::hex >> byte;
        key[i] = static_cast<uint8_t>(byte);
    }
}

int main() {

//    cout << "Original State For Test" << endl;
//    printState(state);
//
//    cout << "Checking KeyExpansion Routine" << endl;
//    uint32_t* w = aesencryption->KeyExpansion(key, 4, 10);
//    for (int i = 0; i < 44; i++) {
//        cout << "0x" << setw(8) << setfill('0') << hex << w[i] << " ";
//        if ((i + 1) % 4 == 0) {
//            cout << endl;
//        }
//    }
//    cout << endl;
//
//    cout << "Checking SubBytes Method" << endl;
//    aesencryption->subBytes(state);
//    // check that state == sub
//    printState(state);
//
//    cout << "Checking ShiftRows Method" << endl;
//    aesencryption->shiftRows(state);
//    // check that state == shift
//    printState(state);
//
//    cout << "Checking MixColumns Method" << endl;
//    aesencryption->mixColumns(state);
//    printState(state);
//
//    cout << "Checking AddRoundKey Method" << endl;
//    aesencryption->addRoundKey(state, w, 1);
//    printState(state);
//
//    cout << "Checking the Cipher Routing" << endl;
//    aesencryption->cipher(in, out, w);
//    for (int j = 0; j < 16; j++) {
//        cout << "0x" << setw(2) << setfill('0') << hex << (int)out[j] << " ";
//    }
//    cout << endl;

    const char* plaintext = "00112233445566778899aabbccddeeff";
    const char* skey = "000102030405060708090a0b0c0d0e0f";
    uint8_t key[16], ptext[16], out[16];

    hexStringToUint8Key(skey, key);
    hexStringToUint8Key(plaintext, ptext);

    AES* aesencryption = new AES();
    uint32_t* w = aesencryption->KeyExpansion(key, 4, 10);

    aesencryption->cipher(ptext, out, w);

    return 0;
}
