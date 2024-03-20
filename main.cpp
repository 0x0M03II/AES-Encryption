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
    //char skey[];
    //char* plaintext;
    AES* aesencryption = new AES(); // instantiate
    uint8_t key[16], ptext[16], out[16], out2[16];

    // AES 128-Bit Encryption
    Nk = 4; Nr = 10;
    char skey[] = "000102030405060708090a0b0c0d0e0f";
    char plaintext[] = "00112233445566778899aabbccddeeff";

    // print header
    printf("C.1   AES-128 (Nk=%d, Nr=%d)\n", Nk, Nr);
    cout << endl;
    printf("PLAINTEXT:          %s\n", plaintext);
    printf("KEY:                %s\n", skey);
    cout << endl;
    printf("CIPHER (ENCRYPT):\n");

    // assign member and conversion
    aesencryption->updatePlaintext(plaintext); // assign member variable
    one_hexStringToUint8Key(skey, key); // convert hex to int
    pthexStringToUint8Key(plaintext, ptext); //convert hex to int

    // encryption algo
    w = aesencryption->KeyExpansion(key, Nk, Nr); // exand key
    aesencryption->cipher(ptext, out, w, Nr); // encrypt
    cout << endl;

    // AES-128 Decrypt
    printf("INVERSE CIPHER (DECRYPT):\n");
    char decr[] = "69c4e0d86a7b0430d8cdb78070b4c55a";
    aesencryption->updatePlaintext(decr);
    aesencryption->invCipher(out, out2, w, Nr); // decryption
    cout << endl;

    // AES 192-bit Encryption
    Nk = 6; Nr = 12;
    char p192[] = "00112233445566778899aabbccddeeff";
    char s192[] = "000102030405060708090a0b0c0d0e0f1011121314151617";

    // print header
    printf("C.2   AES-192 (Nk=%d, Nr=%d)\n", Nk, Nr);
    cout << endl;
    printf("PLAINTEXT:          %s\n", p192);
    printf("KEY:                %s\n", s192);
    cout << endl;
    printf("CIPHER (ENCRYPT):\n");

    // assign member and conversion
    aesencryption->updatePlaintext(p192);
    two_hexStringToUint8Key(s192, key);
    pthexStringToUint8Key(p192, ptext);

    // encryption algo
    w = aesencryption->KeyExpansion(key, Nk, Nr); // key exansion
    aesencryption->cipher(ptext, out, w, Nr); // encryption
    cout << endl;

    // AES-192 Decrypt
    printf("INVERSE CIPHER (DECRYPT):\n");
    char d192[] = "dda97ca4864cdfe06eaf70a0ec0d7191";
    aesencryption->updatePlaintext(d192);
    aesencryption->invCipher(out, out2, w, Nr);
    cout << endl;


    // AES 256-bit Encryption
    Nk = 8; Nr = 14;
    char p256[] = "00112233445566778899aabbccddeeff";
    char s256[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // print header
    printf("C.3   AES-256 (Nk=%d, Nr=%d)\n", Nk, Nr);
    cout << endl;
    printf("PLAINTEXT:          %s\n", p256);
    printf("KEY:                %s\n", s256);
    cout << endl;
    printf("CIPHER (ENCRYPT):\n");

    // assign member and convert
    aesencryption->updatePlaintext(p256);
    three_hexStringToUint8Key(s256, key);
    pthexStringToUint8Key(p256, ptext);

    // encryption algo
    w = aesencryption->KeyExpansion(key, Nk, Nr); // key expansion
    aesencryption->cipher(ptext, out, w, Nr); // encryption
    cout << endl;

    // AES-256 decrypt
    printf("INVERSE CIPHER (DECRYPT):\n");
    char d256[] = "8ea2b7ca516745bfeafc49904b496089";
    aesencryption->updatePlaintext(d256);
    aesencryption->invCipher(out, out2, w, Nr);
    cout << endl;

    return 0;
}
