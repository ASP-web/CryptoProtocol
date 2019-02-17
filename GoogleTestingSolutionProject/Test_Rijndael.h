#ifndef TEST_RIJNDAEL
#define TEST_RIJNDAEL

#include "../AES256_BlocksCipher/Rijndael.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

using ::testing::AtLeast;
using ::testing::Return;
using ::testing::_;

using namespace std;

/*Unit Test Rijndael Algorithm*/

class RijndaelTestCryptAES128 : public ::testing::Test {
public:
	Rijndael* rInstance{ nullptr };

protected:
	void SetUp() override {
		rInstance = new Rijndael;

		(*rInstance->State)[0][0] = 0x19;
		(*rInstance->State)[1][0] = 0xa0;
		(*rInstance->State)[2][0] = 0x9a;
		(*rInstance->State)[3][0] = 0xe9;

		(*rInstance->State)[0][1] = 0x3d;
		(*rInstance->State)[1][1] = 0xf4;
		(*rInstance->State)[2][1] = 0xc6;
		(*rInstance->State)[3][1] = 0xf8;

		(*rInstance->State)[0][2] = 0xe3;
		(*rInstance->State)[1][2] = 0xe2;
		(*rInstance->State)[2][2] = 0x8d;
		(*rInstance->State)[3][2] = 0x48;

		(*rInstance->State)[0][3] = 0xbe;
		(*rInstance->State)[1][3] = 0x2b;
		(*rInstance->State)[2][3] = 0x2a;
		(*rInstance->State)[3][3] = 0x08;
	}

	void TearDown() override { delete rInstance; }
};

class RijndaelTestDecryptAES128 : public ::testing::Test {
public:
	Rijndael* rInstance{ nullptr };

protected:
	void SetUp() override {
		rInstance = new Rijndael;

		(*rInstance->State)[0][0] = 0x7a;
		(*rInstance->State)[0][1] = 0xd5;
		(*rInstance->State)[0][2] = 0xfd;
		(*rInstance->State)[0][3] = 0xa7;

		(*rInstance->State)[1][0] = 0x89;
		(*rInstance->State)[1][1] = 0xef;
		(*rInstance->State)[1][2] = 0x4e;
		(*rInstance->State)[1][3] = 0x27;

		(*rInstance->State)[2][0] = 0x2b;
		(*rInstance->State)[2][1] = 0xca;
		(*rInstance->State)[2][2] = 0x10;
		(*rInstance->State)[2][3] = 0x0b;

		(*rInstance->State)[3][0] = 0x3d;
		(*rInstance->State)[3][1] = 0x9f;
		(*rInstance->State)[3][2] = 0xf5;
		(*rInstance->State)[3][3] = 0x9f;
	}

	void TearDown() override { delete rInstance; }
};

TEST_F(RijndaelTestCryptAES128, BuildRijndaelInstance) {
	ASSERT_NE(rInstance, nullptr);
};

TEST_F(RijndaelTestCryptAES128, CorrectWorkFunctionSubBytes_Round1) {
	rInstance->SubBytes();

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0xd4;
	CurrentState[1][0] = 0xe0;
	CurrentState[2][0] = 0xb8;
	CurrentState[3][0] = 0x1e;

	CurrentState[0][1] = 0x27;
	CurrentState[1][1] = 0xbf;
	CurrentState[2][1] = 0xb4;
	CurrentState[3][1] = 0x41;

	CurrentState[0][2] = 0x11;
	CurrentState[1][2] = 0x98;
	CurrentState[2][2] = 0x5d;
	CurrentState[3][2] = 0x52;

	CurrentState[0][3] = 0xae;
	CurrentState[1][3] = 0xf1;
	CurrentState[2][3] = 0xe5;
	CurrentState[3][3] = 0x30;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { ASSERT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
};

TEST_F(RijndaelTestCryptAES128, CorrectWorkShiftRowsFunction_Round1) {
	rInstance->SubBytes();
	rInstance->ShiftRows();

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0xd4;
	CurrentState[1][0] = 0xe0;
	CurrentState[2][0] = 0xb8;
	CurrentState[3][0] = 0x1e;

	CurrentState[0][1] = 0xbf;
	CurrentState[1][1] = 0xb4;
	CurrentState[2][1] = 0x41;
	CurrentState[3][1] = 0x27;

	CurrentState[0][2] = 0x5d;
	CurrentState[1][2] = 0x52;
	CurrentState[2][2] = 0x11;
	CurrentState[3][2] = 0x98;

	CurrentState[0][3] = 0x30;
	CurrentState[1][3] = 0xae;
	CurrentState[2][3] = 0xf1;
	CurrentState[3][3] = 0xe5;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { ASSERT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
};

TEST_F(RijndaelTestCryptAES128, CorrectWorkFunctionMixColomns_Round1) {
	rInstance->SubBytes();
	rInstance->ShiftRows();
	rInstance->MixColomns();

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0x04;
	CurrentState[1][0] = 0xe0;
	CurrentState[2][0] = 0x48;
	CurrentState[3][0] = 0x28;

	CurrentState[0][1] = 0x66;
	CurrentState[1][1] = 0xcb;
	CurrentState[2][1] = 0xf8;
	CurrentState[3][1] = 0x06;

	CurrentState[0][2] = 0x81;
	CurrentState[1][2] = 0x19;
	CurrentState[2][2] = 0xd3;
	CurrentState[3][2] = 0x26;

	CurrentState[0][3] = 0xe5;
	CurrentState[1][3] = 0x9a;
	CurrentState[2][3] = 0x7a;
	CurrentState[3][3] = 0x4c;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
}

TEST_F(RijndaelTestCryptAES128, CorrectWorkFunctionKeyExpansion_Round10) {
	rInstance->Key = new vector<uint8_t>{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	rInstance->KeyExpansion();
	
	vector<vector<uint8_t>> CurrentKey(4, vector<uint8_t>(4, 0));

	CurrentKey[0][0] = 0xd0;
	CurrentKey[1][0] = 0xc9;
	CurrentKey[2][0] = 0xe1;
	CurrentKey[3][0] = 0xb6;

	CurrentKey[0][1] = 0x14;
	CurrentKey[1][1] = 0xee;
	CurrentKey[2][1] = 0x3f;
	CurrentKey[3][1] = 0x63;

	CurrentKey[0][2] = 0xf9;
	CurrentKey[1][2] = 0x25;
	CurrentKey[2][2] = 0x0c;
	CurrentKey[3][2] = 0x0c;

	CurrentKey[0][3] = 0xa8;
	CurrentKey[1][3] = 0x89;
	CurrentKey[2][3] = 0xc8;
	CurrentKey[3][3] = 0xa6;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentKey[i][j], (*rInstance->RoundKeys)[(i + 10 * 4) * 4 + j]); }
	}
}

TEST_F(RijndaelTestCryptAES128, CorrectWorkFunctionAddRoundKey_Round1) {
	rInstance->Key = new vector<uint8_t>{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	rInstance->KeyExpansion();

	rInstance->SubBytes();
	rInstance->ShiftRows();
	rInstance->MixColomns();
	rInstance->AddRoundKey(1);

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0xa4;
	CurrentState[1][0] = 0x68;
	CurrentState[2][0] = 0x6b;
	CurrentState[3][0] = 0x02;

	CurrentState[0][1] = 0x9c;
	CurrentState[1][1] = 0x9f;
	CurrentState[2][1] = 0x5b;
	CurrentState[3][1] = 0x6a;

	CurrentState[0][2] = 0x7f;
	CurrentState[1][2] = 0x35;
	CurrentState[2][2] = 0xea;
	CurrentState[3][2] = 0x50;

	CurrentState[0][3] = 0xf2;
	CurrentState[1][3] = 0x2b;
	CurrentState[2][3] = 0x43;
	CurrentState[3][3] = 0x49;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
}

TEST_F(RijndaelTestCryptAES128, CorrectWorkFunctionEncrypt) {
	auto byarrKey = new vector<uint8_t>{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	ASSERT_EQ(byarrKey->size(), 16);

	vector<uint8_t>* byarrBufferPublicText = new vector<uint8_t>{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	ASSERT_EQ(byarrBufferPublicText->size() % 16, 0);

	vector<uint8_t>* byarrBufferCipherText = rInstance->Encrypt(byarrBufferPublicText, byarrKey);
	ASSERT_EQ(byarrBufferCipherText->size(), 16);

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0x39;
	CurrentState[1][0] = 0x02;
	CurrentState[2][0] = 0xdc;
	CurrentState[3][0] = 0x19;

	CurrentState[0][1] = 0x25;
	CurrentState[1][1] = 0xdc;
	CurrentState[2][1] = 0x11;
	CurrentState[3][1] = 0x6a;

	CurrentState[0][2] = 0x84;
	CurrentState[1][2] = 0x09;
	CurrentState[2][2] = 0x85;
	CurrentState[3][2] = 0x0b;

	CurrentState[0][3] = 0x1d;
	CurrentState[1][3] = 0xfb;
	CurrentState[2][3] = 0x97;
	CurrentState[3][3] = 0x32;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { ASSERT_EQ(CurrentState[i][j], (*byarrBufferCipherText)[i * 4 + j]); }
	}
}

TEST_F(RijndaelTestDecryptAES128, BuildRijndaelInstance) {
	ASSERT_NE(rInstance, nullptr);
};

TEST_F(RijndaelTestDecryptAES128, CorrectWorkFunctionInvShiftRows) {
	rInstance->InvShiftRows();

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0x7a;
	CurrentState[0][1] = 0x9f;
	CurrentState[0][2] = 0x10;
	CurrentState[0][3] = 0x27;

	CurrentState[1][0] = 0x89;
	CurrentState[1][1] = 0xd5;
	CurrentState[1][2] = 0xf5;
	CurrentState[1][3] = 0x0b;

	CurrentState[2][0] = 0x2b;
	CurrentState[2][1] = 0xef;
	CurrentState[2][2] = 0xfd;
	CurrentState[2][3] = 0x9f;

	CurrentState[3][0] = 0x3d;
	CurrentState[3][1] = 0xca;
	CurrentState[3][2] = 0x4e;
	CurrentState[3][3] = 0xa7;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
}

TEST_F(RijndaelTestDecryptAES128, CorrectWorkFunctionInvSubBytes) {
	rInstance->InvShiftRows();
	rInstance->InvSubBytes();

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0xbd;
	CurrentState[0][1] = 0x6e;
	CurrentState[0][2] = 0x7c;
	CurrentState[0][3] = 0x3d;

	CurrentState[1][0] = 0xf2;
	CurrentState[1][1] = 0xb5;
	CurrentState[1][2] = 0x77;
	CurrentState[1][3] = 0x9e;

	CurrentState[2][0] = 0x0b;
	CurrentState[2][1] = 0x61;
	CurrentState[2][2] = 0x21;
	CurrentState[2][3] = 0x6e;

	CurrentState[3][0] = 0x8b;
	CurrentState[3][1] = 0x10;
	CurrentState[3][2] = 0xb6;
	CurrentState[3][3] = 0x89;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
}

TEST_F(RijndaelTestDecryptAES128, CorrectWorkFunctionInvMixColomns) {
	rInstance->InvShiftRows();
	rInstance->InvSubBytes();
	rInstance->InvMixColomns();

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0x47;
	CurrentState[0][1] = 0x73;
	CurrentState[0][2] = 0xb9;
	CurrentState[0][3] = 0x1f;

	CurrentState[1][0] = 0xf7;
	CurrentState[1][1] = 0x2f;
	CurrentState[1][2] = 0x35;
	CurrentState[1][3] = 0x43;

	CurrentState[2][0] = 0x61;
	CurrentState[2][1] = 0xcb;
	CurrentState[2][2] = 0x01;
	CurrentState[2][3] = 0x8e;

	CurrentState[3][0] = 0xa1;
	CurrentState[3][1] = 0xe6;
	CurrentState[3][2] = 0xcf;
	CurrentState[3][3] = 0x2c;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
}

TEST_F(RijndaelTestDecryptAES128, CorrectWorkFunctionDecrypt) {
	auto byarrKey = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	ASSERT_EQ(byarrKey->size(), 16);

	vector<uint8_t>* byarrBufferCipherText = new vector<uint8_t>{ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
	ASSERT_EQ(byarrBufferCipherText->size() % 16, 0);

	vector<uint8_t>* byarrBufferPlainText = rInstance->Decrypt(byarrBufferCipherText, byarrKey);
	ASSERT_EQ(byarrBufferPlainText->size(), 16);

	vector<vector<uint8_t>> CurrentState(4, vector<uint8_t>(4, 0));

	CurrentState[0][0] = 0x00;
	CurrentState[0][1] = 0x11;
	CurrentState[0][2] = 0x22;
	CurrentState[0][3] = 0x33;

	CurrentState[1][0] = 0x44;
	CurrentState[1][1] = 0x55;
	CurrentState[1][2] = 0x66;
	CurrentState[1][3] = 0x77;

	CurrentState[2][0] = 0x88;
	CurrentState[2][1] = 0x99;
	CurrentState[2][2] = 0xaa;
	CurrentState[2][3] = 0xbb;

	CurrentState[3][0] = 0xcc;
	CurrentState[3][1] = 0xdd;
	CurrentState[3][2] = 0xee;
	CurrentState[3][3] = 0xff;

	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { EXPECT_EQ(CurrentState[i][j], (*rInstance->State)[i][j]); }
	}
}

/*Rijndael Mock Test Functions*/

class RijndaelMock : public Rijndael {
public:
	MOCK_METHOD0(SubBytes, void());
	MOCK_METHOD0(ShiftRows, void());
	MOCK_METHOD0(MixColomns, void());
	MOCK_METHOD0(AddRoundKey, void());
	MOCK_METHOD0(KeyExpansion, void());
	MOCK_METHOD1(AdditionBlocksRatio, vector<uint8_t>*(vector<uint8_t>* arrbyBufferPublicText));
	MOCK_METHOD1(Encrypt, vector<uint8_t>*(vector<uint8_t>* arrbyBufferPublicText));

	MOCK_METHOD0(InvShiftRows, void());
	MOCK_METHOD0(InvSubBytes, void());
	MOCK_METHOD0(InvMixColomns, void());
	MOCK_METHOD1(Decrypt, vector<uint8_t>*(vector<uint8_t>* arrbyByfferCipherText));
};

class RijndaelMockTest :public ::testing::Test {
public:
	RijndaelMock* rmockInstance{ nullptr };

protected:
	void SetUp() override {
		rmockInstance = new RijndaelMock;
	}

	void TearDown() override {
		delete rmockInstance;
	}
};

TEST_F(RijndaelMockTest, CorrectCallFunctionSubBytes) {
	EXPECT_CALL(*rmockInstance, SubBytes()).Times(AtLeast(1));
	rmockInstance->SubBytes();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionShiftRows) {
	EXPECT_CALL(*rmockInstance, ShiftRows()).Times(AtLeast(1));
	rmockInstance->ShiftRows();
}

TEST_F(RijndaelMockTest, CorrectWorkFunctionMixColomns) {
	EXPECT_CALL(*rmockInstance, MixColomns()).Times(AtLeast(1));
	rmockInstance->MixColomns();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionAddRoundKey) {
	EXPECT_CALL(*rmockInstance, AddRoundKey()).Times(AtLeast(1));
	rmockInstance->AddRoundKey();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionKeyExpansion) {
	EXPECT_CALL(*rmockInstance, KeyExpansion()).Times(AtLeast(1));
	rmockInstance->KeyExpansion();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionAdditionBlocksRatio) {
	EXPECT_CALL(*rmockInstance, AdditionBlocksRatio(_)).Times(AtLeast(1));
	rmockInstance->AdditionBlocksRatio(nullptr);
}

TEST_F(RijndaelMockTest, CorrectCallFunctionAdditionEncrypt) {
	EXPECT_CALL(*rmockInstance, Encrypt(_)).Times(AtLeast(1));
	rmockInstance->Encrypt(nullptr);
}

TEST_F(RijndaelMockTest, CorrectCallFunctionInvShiftRows) {
	EXPECT_CALL(*rmockInstance, InvShiftRows()).Times(AtLeast(1));
	rmockInstance->InvShiftRows();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionInvSubBytes) {
	EXPECT_CALL(*rmockInstance, InvSubBytes()).Times(AtLeast(1));
	rmockInstance->InvSubBytes();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionInvMixColomns) {
	EXPECT_CALL(*rmockInstance, InvMixColomns()).Times(AtLeast(1));
	rmockInstance->InvMixColomns();
}

TEST_F(RijndaelMockTest, CorrectCallFunctionDecrypt) {
	EXPECT_CALL(*rmockInstance, Decrypt(_)).Times(AtLeast(1));
	rmockInstance->Decrypt(nullptr);
}

#endif //TEST_RIJNDAEL