#ifndef TEST_ECPOINT_H
#define TEST_ECPOINT_H

#include "../ECDSA/ECDSA.h"
#include "../CSPRNG/CSPRNG.h"
#include "gtest/gtest.h"
#include <string>
#include <iostream>

using namespace std;

/*Unit Test ECPoint Class*/
class ECDSATestEllipticCurvePoint : public ::testing::Test {
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

TEST_F(ECDSATestEllipticCurvePoint, CorrectWorkFunctionReverseElementInField) {
	bigint a("-34235449");
	bigint mod("34235453");

	ECPoint Point(rInstanceECDSA);
	auto c = Point.ReverseElementInField(a, mod);

	ASSERT_STREQ(c.ToString().data(), "25676590");
}

TEST_F(ECDSATestEllipticCurvePoint, CorrectWorkAssignmentOperator) {
	string x1("1111");
	string y1("2222");

	string x2("3333");
	string y2("4444");

	ECPoint Point1(rInstanceECDSA);
	ECPoint Point2(rInstanceECDSA);

	Point1.setCoordinate(x1, y1);
	Point2.setCoordinate(x2, y2);

	Point1 = Point2;

	ASSERT_STREQ(Point1._x.ToString().data(), x2.data());
	ASSERT_STREQ(Point1._y.ToString().data(), y2.data());

}

TEST_F(ECDSATestEllipticCurvePoint, CorrectWorkPlusOperator) {
	rInstanceECDSA->_a.FromString("-3", 10);
	rInstanceECDSA->_p.FromString("5", 10);

	string x1("1");
	string y1("2");

	string x2("3");
	string y2("4");

	ECPoint Point1(rInstanceECDSA);
	ECPoint Point2(rInstanceECDSA);
	ECPoint Point3(rInstanceECDSA);
	ECPoint Point4(rInstanceECDSA);
	ECPoint Point5(rInstanceECDSA);

	Point1.setCoordinate(x1, y1);
	Point2.setCoordinate(x2, y2);


	/*First I Condition*/
	Point3 = Point1 + Point2;

	ASSERT_STREQ(Point3._x.ToString().data(), "2");
	ASSERT_STREQ(Point3._y.ToString().data(), "2");

	/*Second II Condition*/
	Point4 = Point3 + Point3;

	ASSERT_STREQ(Point4._x.ToString().data(), "2");
	ASSERT_STREQ(Point4._y.ToString().data(), "3");

	/*Third III Condition (Null Elliptic Curve Point)*/
	Point5 = Point3 + Point4;

	ASSERT_STREQ(Point5._x.ToString().data(), "-1");
	ASSERT_STREQ(Point5._y.ToString().data(), "-1");
}

TEST_F(ECDSATestEllipticCurvePoint, CorrectWorkMultiplytOperator) {
	rInstanceECDSA->_a.FromString("-3", 10);
	rInstanceECDSA->_p.FromString("5", 10);

	string x1("1");
	string y1("2");

	ECPoint Point1(rInstanceECDSA);
	ECPoint Point2(rInstanceECDSA);

	Point1.setCoordinate(x1, y1);

	Point2 = Point1 * 2;

	EXPECT_STREQ(Point2._x.ToString().data(), "3");
	EXPECT_STREQ(Point2._y.ToString().data(), "3");

	Point2 = Point1 * 3;

	EXPECT_STREQ(Point2._x.ToString().data(), "0");
	EXPECT_STREQ(Point2._y.ToString().data(), "1");
}


TEST_F(ECDSATestEllipticCurvePoint, TestNIST) {
	rInstanceECDSA->_a.FromString("-3", 10);
	rInstanceECDSA->_p.FromString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10);
	rInstanceECDSA->_Gx.FromString("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846", 10);
	rInstanceECDSA->_Gy.FromString("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784", 10);
	rInstanceECDSA->_n.FromString("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", 10);

	string x1("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846");
	string y1("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784");

	ECPoint Point1(rInstanceECDSA);
	ECPoint Point2(rInstanceECDSA);

	/*Point1 = G in NIST, _n = n in NIST*/
	Point1.setCoordinate(x1, y1);

	/*In NIST nG = 0 - NULL Point (In our Arithmetics: NULL Point = (-1, -1))*/
	Point2 = Point1 * rInstanceECDSA->_n;

	EXPECT_STREQ(Point2._x.ToString().data(), "-1");
	EXPECT_STREQ(Point2._y.ToString().data(), "-1");
}

TEST_F(ECDSATestEllipticCurvePoint, TestGOST) {
	rInstanceECDSA->_a.FromString("7", 10);
	rInstanceECDSA->_p.FromString("57896044618658097711785492504343953926634992332820282019728792003956564821041", 10);
	rInstanceECDSA->_b.FromString("43308876546767276905765904595650931995942111794451039583252968842033849580414", 10);
	rInstanceECDSA->_Gx.FromString("2", 10);
	rInstanceECDSA->_Gy.FromString("4018974056539037503335449422937059775635739389905545080690979365213431566280", 10);
	rInstanceECDSA->_n.FromString("57896044618658097711785492504343953927082934583725450622380973592137631069619", 10);

	string x1("2");
	string y1("4018974056539037503335449422937059775635739389905545080690979365213431566280");

	ECPoint Point1(rInstanceECDSA);
	ECPoint Point2(rInstanceECDSA);

	/*Point1 = P in GOST, _n = q in GOST*/
	Point1.setCoordinate(x1, y1);

	/*In GOST qP = 0 - NULL Point (In our Arithmetics: NULL Point = (-1, -1))*/
	Point2 = Point1 * rInstanceECDSA->_n;
	EXPECT_STREQ(Point2._x.ToString().data(), "-1");
	EXPECT_STREQ(Point2._y.ToString().data(), "-1");
}

#endif //TEST_ECPOINT_H