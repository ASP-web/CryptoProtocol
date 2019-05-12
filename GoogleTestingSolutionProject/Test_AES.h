#ifndef TEST_AES_H
#define TEST_AES_H

#include "../AES256_BlocksCipher/AES.h"
#include "../AES256_BlocksCipher/Rijndael.h"
#include "gtest/gtest.h"
#include <chrono>

using namespace std;

/*Unit Test AES 128/192/256 BlocksCipher*/

class TestAES : public ::testing::Test {};

/*Big Input Size TESTS*/
//ECB
TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES128_ECB) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_128 aes;
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES128_ECB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES128_ECB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES192_ECB) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_192 aes;
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES192_ECB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES192_ECB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES256_ECB) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_256 aes;
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES256_ECB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES256_ECB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

//CTR
TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES128_CTR) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_128 aes;
	aes.SetEncryptionMode(1);
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES128_CTR time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES128_CTR time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES192_CTR) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_192 aes;
	aes.SetEncryptionMode(1);
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES192_CTR time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES192_CTR time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES256_CTR) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_256 aes;
	aes.SetEncryptionMode(1);
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES256_CTR time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES256_CTR time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

//OFB
TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES128_OFB) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_128 aes;
	aes.SetEncryptionMode(2);
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES128_OFB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES128_OFB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES192_OFB) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_192 aes;
	aes.SetEncryptionMode(2);
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES192_OFB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES192_OFB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}

TEST_F(TestAES, CorrectWorkEncryptAndDecryptAES256_OFB) {
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

	AES_256 aes;
	aes.SetEncryptionMode(2);
	vector<uint8_t>* key = new vector<uint8_t>{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	vector<uint8_t>* PT = new vector<uint8_t>(10485760, 'a');

	start = myclock::now();
	vector<uint8_t>* calcCT = aes.Encrypt(PT, key);
	end = myclock::now();
	cout << "Encrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES256_OFB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	vector<uint8_t>* calcPT = aes.Decrypt(calcCT, key);
	end = myclock::now();
	cout << "Decrypt_" << PT->size() / (1024 * 1024) << "Mbyte_AES256_OFB time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	for (uint64_t i = 0; i < PT->size(); i++) { EXPECT_EQ((*calcPT)[i], (*PT)[i]); }

	delete key;
	delete PT;
	delete calcCT;
	delete calcPT;
}


#endif //TEST_AES_H