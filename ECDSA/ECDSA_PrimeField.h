#ifndef ECDSA_PrimeField_H
#define ECDSA_PrimeField_H

#include "ttmath/ttmath.h"
#include "ttmath/ttmathint.h"

#include <iostream>
#include <string>
#include <memory>

using namespace std;

using bigint = ttmath::Int<32>;

/*Class ECDSA_PrimeField*/
class ECDSA_PrimeField {
private:
	/*Curve Coefficients*/
	bigint _a;			// Coefficient 'a' of Curve equal y^2 = x^3 + a*x + b (mod p) | Anallogically abbreviation in GOST 34.10-2012
	bigint _b;			// Coefficient 'b' of Curve equal y^2 = x^3 + a*x + b (mod p) | Anallogically abbreviation in GOST 34.10-2012
	bigint _p;			// Prime module of Curve equal y^2 = x^3 + a*x + b (mod p) | Anallogically abbreviation in GOST 34.10-2012
	bigint _Gx;			// Coordinate 'x' of Point G of Elliptical Curve [ y^2 = x^3 + a*x + b (mod p) ] order n | In GOST 34.10-2012 it is 'x' coordinate of point P
	bigint _Gy;			// Coordinate 'y' of Point G of Elliptical Curve [ y^2 = x^3 + a*x +b (mod p) ] order n | In GOST 34.10-2012 it is 'y' coordinate of point P
	bigint _n;			// Order of SubGroup of Points of Elliptical Curve [ y^2 = x^3 + a*x + b (mod p) ] | In GOST 34.10-2012 it is 'q' parametr

	string hexStr(vector<uint8_t>* hexArray);

public:
	//Return Public parameters : first - 'r', second - 's'
	pair<string, string> CreateDigitalSign(const string& PrivateKeyDigitalSign, const string& Message);

	bool CheckDigitalSign(const pair<string, string>& DigitalSign, const string& Message, const pair<string, string>& KeyCheckDigitalSign);

	//Return KeyCheckDigitalSign <=>  Public Elliptic Curve Point Q : first - 'x' coordinate of Q point, second - 'y' coordinate of Q point, [PrivateKeyDigitalSign is Big number in dec system]
	pair<string, string> CreateKeyCheckDigitalSign(const string& PrivateKeyDigitalSign);

	pair<string, string> MultiplyOnBasePoint(const bigint& Number);

public:
	ECDSA_PrimeField(bigint& a, bigint& b, bigint& p, bigint& Gx, bigint& Gy, bigint& n);

	~ECDSA_PrimeField();

	friend class ECPoint;
};

/*Class ECPoint*/
class ECPoint {
private:
	/*Elliptical Curve Point Coordinates 'x' and 'y' */
	bigint _x;
	bigint _y;
	ECDSA_PrimeField* _parentECDSA{ nullptr };
	
	ECPoint DoubleAndAdd(const bigint& k, const ECPoint& point);

	static bigint ReverseElementInField(const bigint& Element, const bigint& Module);

	static void ExtendedEuclidAlgorithm(bigint& a, bigint& b, bigint& x, bigint& y, bigint& d);

public:

	void setCoordinate(const string& x, const string& y);

	string getXCoordinate();
	
	string getYCoordinate();

	ECPoint& operator = (const ECPoint& rhs);

	ECPoint operator + (const ECPoint& rhs);

	ECPoint operator * (const bigint& rhs);

	bool operator == (const ECPoint& rhs);

	ECPoint(ECDSA_PrimeField* parentECDSA);

	~ECPoint();

	friend class ECDSA_PrimeField;
};

#endif //ECDSA_PRIMEFIELD_H