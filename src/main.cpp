#include <iostream>
#include "aes.h"

using namespace std;

int main() {
    // uint32_t t = subWord(0x8090a0b0);
    // uint32_t p = subWord(0xc0d0e0f0);

    // cout << hex << t << endl;
    // cout << hex << p << endl;

    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };


    AES* aesencryption = new AES();

    uint32_t* expanded =
            aesencryption->KeyExpansion(key, 4, 10);

    for (int i = 0; i < 44; i++) {
        cout << hex << expanded[i] << endl;
    }

    return 0;
}
