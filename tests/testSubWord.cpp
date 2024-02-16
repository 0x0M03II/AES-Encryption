#include "../aes.h"
#include <gtest/gtest.h>
#include <memory>

class AESTest : public ::testing::Test {
protected:
    std::unique_ptr<AES> encryptionTests;

    void SetUp() override {
        encryptionTests = std::make_unique<AES>();
    }
};

TEST_F(AESTest, SubWordTest) {
    EXPECT_EQ(encryptionTests->subWord(0x00102030), 0x63cab704) << "subWord failed for input 0x00102030";
    EXPECT_EQ(encryptionTests->subWord(0x40506070), 0x0953d051) << "subWord failed for input 0x40506070";
    EXPECT_EQ(encryptionTests->subWord(0x8090a0b0), 0xcd60e0e7) << "subWord failed for input 0x8090a0b0";
    EXPECT_EQ(encryptionTests->subWord(0xc0d0e0f0), 0xba70e18c) << "subWord failed for input 0xc0d0e0f0";
}