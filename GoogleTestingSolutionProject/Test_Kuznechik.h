#pragma once

#include "../Kuznechik/Kuznechik.h"
#include "gtest/gtest.h"
#include <fstream>
#include <chrono>

using namespace std;

class TestKuznechik : public ::testing::Test {
public:
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;
};

TEST_F(TestKuznechik, CorrectWorkKuznechik) {
	KUZNECHIK CIPHER_GOST;

	auto GOST_PT = new vector<uint8_t>{ 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
	auto GOST_CT = new vector<uint8_t>{ 0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f };
	auto GOST_KEY = new vector<uint8_t>{ 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

	start = myclock::now();
	vector<uint8_t> CALCULATE_CT = CIPHER_GOST.EncryptionBlock(GOST_PT, GOST_KEY);
	end = myclock::now();
	cout << "GOST (Kuznechik) Encryption calculation time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;
	
	for (unsigned char i : CALCULATE_CT) { printf("%x", i); }
	cout << endl;

	for (uint64_t i = 0; i < GOST_CT->size(); i++) { EXPECT_EQ(CALCULATE_CT[i], (*GOST_CT)[i]); }

	start = myclock::now();
	vector<uint8_t> CALCULATE_PT = CIPHER_GOST.DecryptionBlock(GOST_CT, GOST_KEY);
	end = myclock::now();
	cout << "GOST (Kuznechik) Decryption calculation time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (unsigned char i : CALCULATE_PT) { printf("%x", i); }
	cout << endl;

	for (uint64_t i = 0; i < GOST_PT->size(); i++) { EXPECT_EQ(CALCULATE_PT[i], (*GOST_PT)[i]); }
	
	delete GOST_PT;
	delete GOST_CT;
	delete GOST_KEY;
};
