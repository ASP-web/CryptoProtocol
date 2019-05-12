#ifndef TEST_SHA1_H
#define TEST_SHA1_H

#include "../SHA1_Hash/SHA1.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>

/*Unit Test SHA1 Hash Algorithm*/

class SHA1Test : public ::testing::Test {
public:
	SHA1* rInstance{ nullptr };

protected:
	void SetUp() override {
		rInstance = new SHA1;
	}

	void TearDown() override { delete rInstance; }
};

TEST_F(SHA1Test, CorrectWorkFunctionGetHash_TEST2_0bit) {
	/*Input message "" (empty string) (0 bits)*/
	string StringTest = "";
	vector<uint8_t> CorrectDigest = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 };
	auto SendMessage = new vector<uint8_t>(StringTest.begin(), StringTest.end());
	auto Digest = rInstance->GetHash(SendMessage);

	ASSERT_EQ(CorrectDigest.size(), 20);
	ASSERT_EQ(Digest->size(), 20);

	for (uint8_t i = 0; i < 20; i++) { EXPECT_EQ(CorrectDigest[i], (*Digest)[i]); };

	CorrectDigest.clear();
	delete Digest;
	delete SendMessage;
	StringTest.clear();
}


TEST_F(SHA1Test, CorrectWorkFunctionGetHash_TEST1_24Bit) {
	/*Input message "abc" (24 bits)*/
	string StringTest = "abc";
	vector<uint8_t> CorrectDigest{ 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
	auto SendMessage = new vector<uint8_t>(StringTest.begin(), StringTest.end());
	auto Digest = rInstance->GetHash(SendMessage);

	ASSERT_EQ(CorrectDigest.size(), 20);
	ASSERT_EQ(Digest->size(), 20);

	for (uint8_t i = 0; i < 20; i++) { EXPECT_EQ(CorrectDigest[i], (*Digest)[i]); };

	CorrectDigest.clear();
	delete Digest;
	delete SendMessage;
	StringTest.clear();
}

TEST_F(SHA1Test, CorrectWorkFunctionGetHash_TEST3_448Bit) {
	/*Input message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (448 bits)*/
	string StringTest = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	vector<uint8_t> CorrectDigest = { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };
	auto SendMessage = new vector<uint8_t>(StringTest.begin(), StringTest.end());
	auto Digest = rInstance->GetHash(SendMessage);

	ASSERT_EQ(CorrectDigest.size(), 20);
	ASSERT_EQ(Digest->size(), 20);

	for (uint8_t i = 0; i < 20; i++) { EXPECT_EQ(CorrectDigest[i], (*Digest)[i]); };

	CorrectDigest.clear();
	delete Digest;
	delete SendMessage;
	StringTest.clear();
}

TEST_F(SHA1Test, CorrectWorkFunctionGetHash_TEST4_896Bit) {
	/*Input message "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (896 bits)*/
	string StringTest = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	vector<uint8_t> CorrectDigest = { 0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6, 0x70, 0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59 };
	auto SendMessage = new vector<uint8_t>(StringTest.begin(), StringTest.end());
	auto Digest = rInstance->GetHash(SendMessage);

	ASSERT_EQ(CorrectDigest.size(), 20);
	ASSERT_EQ(Digest->size(), 20);

	for (uint8_t i = 0; i < 20; i++) { EXPECT_EQ(CorrectDigest[i], (*Digest)[i]); };

	CorrectDigest.clear();
	delete Digest;
	delete SendMessage;
	StringTest.clear();
}

TEST_F(SHA1Test, CorrectWorkFunctionGetHash_TEST5_1Mb) {
	/*Input message one million (1,000,000) repetitions of the character 'a' (8 million bits)*/
	string StringTest(1000000, 'a');
	vector<uint8_t> CorrectDigest = { 0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f };
	auto SendMessage = new vector<uint8_t>(StringTest.begin(), StringTest.end());
	auto Digest = rInstance->GetHash(SendMessage);

	ASSERT_EQ(CorrectDigest.size(), 20);
	ASSERT_EQ(Digest->size(), 20);

	for (uint8_t i = 0; i < 20; i++) { EXPECT_EQ(CorrectDigest[i], (*Digest)[i]); };

	CorrectDigest.clear();
	delete Digest;
	delete SendMessage;
	StringTest.clear();
}


#endif // TEST_SHA1_H
