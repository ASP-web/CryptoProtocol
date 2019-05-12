#ifndef TEST_ECDSA_H
#define TEST_ECDSA_H

#include "../ECDSA/ECDSA.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <iostream>
#include <chrono>

using namespace std;

/*Unit Test ECDSA Algorithm*/
class ECDSATest : public ::testing::Test {
public:
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;
protected:
	void SetUp() override {}

	void TearDown() override {}
};

TEST_F(ECDSATest, TEST_ECDSA_GOST_256) {
	ECDSA_GOST_256 GOST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = GOST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_GOST_256 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = GOST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_GOST_256 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = GOST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_GOST_256 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_GOST_512) {
	ECDSA_GOST_512 GOST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = GOST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_GOST_512 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = GOST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_GOST_512 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = GOST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_GOST_512 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_192) {
	ECDSA_NIST_192 NIST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = NIST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_NIST_192 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = NIST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_NIST_192 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = NIST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_NIST_192 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_224) {
	ECDSA_NIST_224 NIST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = NIST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_NIST_224 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = NIST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_NIST_224 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = NIST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_NIST_224 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_256) {
	ECDSA_NIST_256 NIST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = NIST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_NIST_256 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = NIST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_NIST_256 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = NIST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_NIST_256 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_384) {
	ECDSA_NIST_384 NIST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = NIST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_NIST_384 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = NIST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_NIST_384 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = NIST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_NIST_384 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_521) {
	ECDSA_NIST_521 NIST;

	string SecretKey("1234567890098765432112345678900987654321");
	string Message("Hello Alice! My name is Bob!");

	start = myclock::now();
	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = NIST.CreateKeyCheckDigitalSign(SecretKey);
	end = myclock::now();
	cout << "ECDSA_NIST_521 CreateKeyCheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	start = myclock::now();
	//CreateDigitalSign
	pair<string, string> DigitalSign = NIST.CreateDigitalSign(SecretKey, Message);
	end = myclock::now();
	cout << "ECDSA_NIST_521 CreateDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	//Message += "?"; //Change Message  (Attack to integrity)

	start = myclock::now();
	//CheckDigitalSign
	bool result = NIST.CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	end = myclock::now();
	cout << "ECDSA_NIST_521 CheckDigitalSign time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ASSERT_EQ(result, true);
}

#endif //TEST_ECDSA_H