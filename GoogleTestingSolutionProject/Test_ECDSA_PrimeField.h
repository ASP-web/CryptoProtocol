#ifndef TEST_ECDSA_PRIMEFIELD_H
#define TEST_ECDSA_PRIMEFIELD_H

#include "../ECDSA/ECDSA_PrimeField.h"
#include "../CSPRNG/CSPRNG.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <iostream>

using namespace std;

/*Unit Test ECDSA Algorithm*/
class ECDSATest : public ::testing::Test {
public:
	ECDSA_PrimeField* rInstanceECDSA;
protected:
	void SetUp() override {
		rInstanceECDSA = new ECDSA_PrimeField;
	}

	void TearDown() override {
		delete rInstanceECDSA;
	}
};

TEST_F(ECDSATest, CorrectWorkCreateDigitalSignAndCheckDigitalSignFunction_NISTCurveP521) {
	//Initialization parameters
	rInstanceECDSA->_a.FromString("-3", 10);
	rInstanceECDSA->_p.FromString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10);
	rInstanceECDSA->_Gx.FromString("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846", 10);
	rInstanceECDSA->_Gy.FromString("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784", 10);
	rInstanceECDSA->_n.FromString("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", 10);

	string d("1234567890098765432112345678900987654321");

	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = rInstanceECDSA->CreateKeyCheckDigitalSign(d);

	//CreateDigitalSign
	string Message("Hello Alice! My name is Bob!");
	pair<string, string> DigitalSign = rInstanceECDSA->CreateDigitalSign(d, Message);

	//CheckDigitalSign
	bool result = rInstanceECDSA->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, CorrectWorkCreateDigitalSignAndCheckDigitalSignFunction_NISTCurveP192) {
	//Initialization parameters
	rInstanceECDSA->_a.FromString("-3", 10);
	rInstanceECDSA->_p.FromString("6277101735386680763835789423207666416083908700390324961279", 10);
	rInstanceECDSA->_b.FromString("245515554600894381774029391519745178476910805816119123806", 10);
	rInstanceECDSA->_Gx.FromString("602046282375688656758213480587526111916698976636884684818", 10);
	rInstanceECDSA->_Gy.FromString("174050332293622031404857552280219410364023488927386650641", 10);
	rInstanceECDSA->_n.FromString("6277101735386680763835789423176059013767194773182842284081", 10);

	//ECPoint G(rInstanceECDSA);
	//G._x = rInstanceECDSA->_Gx;
	//G._y = rInstanceECDSA->_Gy;

	//ECPoint P(rInstanceECDSA);
	//P = G*rInstanceECDSA->_n;

	//ASSERT_STREQ(P._x.ToString().data(), "-1");
	//ASSERT_STREQ(P._y.ToString().data(), "-1");
	
	string d("1234567890098765432112345678900987654321");

	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = rInstanceECDSA->CreateKeyCheckDigitalSign(d);

	//CreateDigitalSign
	string Message("Hello Alice! My name is Bob!");
	pair<string, string> DigitalSign = rInstanceECDSA->CreateDigitalSign(d, Message);

	//CheckDigitalSign
	bool result = rInstanceECDSA->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, CorrectWorkCreateDigitalSignAndCheckDigitalSignFunction_GOSTCurve) {
	//Initialization parameters
	rInstanceECDSA->_a.FromString("7", 10);
	rInstanceECDSA->_p.FromString("57896044618658097711785492504343953926634992332820282019728792003956564821041", 10);
	rInstanceECDSA->_b.FromString("43308876546767276905765904595650931995942111794451039583252968842033849580414", 10);
	rInstanceECDSA->_Gx.FromString("2", 10);
	rInstanceECDSA->_Gy.FromString("4018974056539037503335449422937059775635739389905545080690979365213431566280", 10);
	rInstanceECDSA->_n.FromString("57896044618658097711785492504343953927082934583725450622380973592137631069619", 10);

	string d("1234567890098765432112345678900987654321");

	//CreateKeyCheckDigitalSign
	pair<string, string> KeyCheckDigitalSign = rInstanceECDSA->CreateKeyCheckDigitalSign(d);

	//CreateDigitalSign
	string Message("Hello Alice! My name is Bob!");
	pair<string, string> DigitalSign = rInstanceECDSA->CreateDigitalSign(d, Message);

	//Message += "?";

	//CheckDigitalSign
	bool result = rInstanceECDSA->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

#endif //TEST_ECDSA_PRIMEFIELD_H