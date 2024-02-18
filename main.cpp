#include <iostream>
#include <sstream>
#include "aes.h"

using namespace std;

void pthexStringToUint8Key(const std::string &hexStr, uint8_t key[16]) {
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        std::istringstream iss(hexStr.substr(i * 2, 2));
        iss >> std::hex >> byte;
        key[i] = static_cast<uint8_t>(byte);
    }
}

void one_hexStringToUint8Key(const std::string &hexStr, uint8_t key[16]) {
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        std::istringstream iss(hexStr.substr(i * 2, 2));
        iss >> std::hex >> byte;
        key[i] = static_cast<uint8_t>(byte);
    }
}

void two_hexStringToUint8Key(const std::string &hexStr, uint8_t key[24]) {
    for (int i = 0; i < 24; i++) {
        unsigned int byte;
        std::istringstream iss(hexStr.substr(i * 2, 2));
        iss >> std::hex >> byte;
        key[i] = static_cast<uint8_t>(byte);
    }
}

void three_hexStringToUint8Key(const std::string &hexStr, uint8_t key[32]) {
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        std::istringstream iss(hexStr.substr(i * 2, 2));
        iss >> std::hex >> byte;
        key[i] = static_cast<uint8_t>(byte);
    }
}

int main() {

    int Nk, Nr;
    uint32_t* w;
    const char* skey;
    const char* plaintext;
    AES* aesencryption = new AES(); // instantiate
    uint8_t key[16], ptext[16], out[16], out2[16];

    // AES 128-Bit Test
    cout << "AES 128-bit Test" << endl;
    Nk = 4; Nr = 10;
    skey = "000102030405060708090a0b0c0d0e0f";
    plaintext = "00112233445566778899aabbccddeeff";
    aesencryption->updatePlaintext("00112233445566778899aabbccddeeff");
    one_hexStringToUint8Key(skey, key);
    pthexStringToUint8Key(plaintext, ptext);
    w = aesencryption->KeyExpansion(key, Nk, Nr);
    aesencryption->cipher(ptext, out, w, Nr);
    cout << endl;
    cout << "AES 128-bit Inverse Test" << endl;
    aesencryption->updatePlaintext("69c4e0d86a7b0430d8cdb78070b4c55a");
    aesencryption->invCipher(out, out2, w, Nr);
    cout << endl;

    // AES 192-bit Test
    cout << "AES 192-bit Test" << endl;
    Nk = 6; Nr = 12;
    plaintext = "00112233445566778899aabbccddeeff";
    skey = "000102030405060708090a0b0c0d0e0f1011121314151617";
    two_hexStringToUint8Key(skey, key);
    pthexStringToUint8Key(plaintext, ptext);
    w = aesencryption->KeyExpansion(key, Nk, Nr);
    aesencryption->cipher(ptext, out, w, Nr);
    cout << endl;

    // AES 256-bit Test
    cout << "AES 256-bit Test" << endl;
    Nk = 8; Nr = 14;
    plaintext = "00112233445566778899aabbccddeeff";
    skey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    three_hexStringToUint8Key(skey, key);
    pthexStringToUint8Key(plaintext, ptext);
    w = aesencryption->KeyExpansion(key, Nk, Nr);
    aesencryption->cipher(ptext, out, w, Nr);
    cout << endl;

    return 0;
}
