#include "ECDSA_PrimeField.h"
#include "../SHA512_Hash/SHA512.h"
#include "../CSPRNG/CSPRNG.h"
#include <list>

using namespace AlgorithmSHA512;

const uint8_t hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

/*Start ECPoint Methods*/
void ECPoint::setCoordinate(const string& x, const string& y){
	_x.FromString(x, 10);
	_y.FromString(y, 10);
};

string ECPoint::getXCoordinate(){ return this->_x.ToString(); }

string ECPoint::getYCoordinate() { return this->_y.ToString(); }

ECPoint ECPoint::DoubleAndAdd(const bigint& k, const ECPoint& pointP){
	
	/*Calculating binary representation of 'k'*/
	bigint CurrentNumberPower2("1");
	int wPower = 0;
	while (CurrentNumberPower2*2 <= k) {
		CurrentNumberPower2 *= 2;
		wPower++;
	}

	list<bool> tempFormatBinaryPowerK;

	bigint tempk;
	tempk = k;
	for (int i = wPower; i >= 0; i--) {
		if (tempk >= CurrentNumberPower2) {
			tempk -= CurrentNumberPower2;
			tempFormatBinaryPowerK.push_front(true);
		}
		else {
			tempFormatBinaryPowerK.push_front(false);
		}
		CurrentNumberPower2 /= 2;
	}

	vector<bool> FormatBinaryPowerK(tempFormatBinaryPowerK.begin(), tempFormatBinaryPowerK.end());

	/*Double And Add Algorithm of Fast Multiplication*/
	ECPoint N(_parentECDSA);
	ECPoint Q(_parentECDSA);

	Q.setCoordinate("-1", "-1");
	N = pointP;
	for (uint16_t i = 0; i < FormatBinaryPowerK.size(); i++) {
		if (FormatBinaryPowerK[i] == 1) {
			Q = Q + N;
		}
		N = N + N;
	}
	return Q;
};

bigint ECPoint::ReverseElementInField(const bigint& Element, const bigint& Module){
	bigint a, b, x, y, d;
	
	a = Element;
	b = Module;
	
	if (a < 0) { a = (a % b) + b; }

	ExtendedEuclidAlgorithm(a, b, x, y, d);

	if (x < 0) { x += Module; }
	return x;
};

void ECPoint::ExtendedEuclidAlgorithm(bigint& a, bigint& b, bigint& x, bigint& y, bigint& d){
	bigint q, r, x1, x2, y1, y2;

	if (b == 0) {		
		x = 0;				
		return;
	}

	x2 = 1;	
	x1 = 0;	
	y2 = 0;	
	y1 = 1;

	while (b > 0) {	
		q = a / b;			
		r = a - q*b;
		x = x2 - q*x1;
		y = y2 - q*y1;
		a = b;
		b = r;
		x2 = x1;
		x1 = x;
		y2 = y1;
		y1 = y;
	}

	d = a;
	x = x2;
	y = y2;
};

/*Check that 2 Points belong to the one common Elliptic Curve*/
bool ECPoint::operator==(const ECPoint& rhs) {
	if (_parentECDSA == rhs._parentECDSA) return true;
	else return false;
};

ECPoint::ECPoint(ECDSA_PrimeField* parentECDSA){
	_parentECDSA = parentECDSA;
	return;
};

ECPoint::~ECPoint(){
	return;
};

ECPoint ECPoint::operator + (const ECPoint& rhs) {
	if (*this == rhs) {
		ECPoint ecp(_parentECDSA);
		if ((rhs._x >= 0 && rhs._y >= 0) && (_x >= 0 && _y >= 0)) {
			if (_x != rhs._x) {

				bigint Lambda = ((rhs._y - _y) *  ReverseElementInField((rhs._x - _x), _parentECDSA->_p)) % _parentECDSA->_p;
				Lambda = Lambda < 0 ? Lambda + _parentECDSA->_p : Lambda;

				ecp._x = ((Lambda*Lambda) - _x - rhs._x) % _parentECDSA->_p;
				ecp._x = ecp._x < 0 ? ecp._x + _parentECDSA->_p : ecp._x;

				ecp._y = ((Lambda*(_x - ecp._x)) - _y) % _parentECDSA->_p;
				ecp._y = ecp._y < 0 ? ecp._y + _parentECDSA->_p : ecp._y;

				return ecp;
			}
			else if ((_x == rhs._x) && (_y == ((-rhs._y) % _parentECDSA->_p < 0 ? ((-rhs._y) % _parentECDSA->_p) + _parentECDSA->_p : (-rhs._y) % _parentECDSA->_p))) {
				ecp._x = -1;
				ecp._y = -1;
				return ecp;
			}
			else if ((_x == rhs._x) && (_y == rhs._y) && (_y != 0) && (rhs._y != 0)) {

				bigint Lambda = (((_x*_x * 3) + _parentECDSA->_a) * ReverseElementInField((_y * 2), _parentECDSA->_p)) % _parentECDSA->_p;
				Lambda = Lambda < 0 ? Lambda + _parentECDSA->_p : Lambda;

				ecp._x = ((Lambda*Lambda) - (_x * 2)) % _parentECDSA->_p;
				ecp._x = ecp._x < 0 ? ecp._x + _parentECDSA->_p : ecp._x;

				ecp._y = ((Lambda*(_x - ecp._x)) - _y) % _parentECDSA->_p;
				ecp._y = ecp._y < 0 ? ecp._y + _parentECDSA->_p : ecp._y;

				return ecp;
			}
		}
		/*Check if in addition attend NULL Elliptic Curve Point*/
		else {
			if (_x == -1 && _y == -1) {
				
				ecp._x = rhs._x;
				ecp._y = rhs._y;
				
				return ecp;
			}
			else if (rhs._x == -1 && rhs._y == -1) {
				
				ecp._x = _x;
				ecp._y = _y;

				return ecp;
			}
			else {
				
				ecp._x = -1;
				ecp._y = -1;

				return ecp;
			}
		}
	}
	else {
		throw 1;
		cout << "here!" << endl;
		return *this;
	}
};

ECPoint ECPoint::operator * (const bigint& rhs) {
	//Check, that 0 < rhs < n
	bigint _d(rhs);
	_d %= (*this->_parentECDSA)._n;
	_d = _d < 0 ? _d + (*this->_parentECDSA)._n : _d;
	return DoubleAndAdd(_d, *this);
};

ECPoint& ECPoint::operator = (const ECPoint& rhs){
	_x = rhs._x;
	_y = rhs._y;
	_parentECDSA = rhs._parentECDSA;
	return *this;
};
/*End ECPoint Methods*/


/*Start ECDSA_PrimeField Methods*/
string ECDSA_PrimeField::hexStr(vector<uint8_t> *data){
	string s(data->size() * 2, ' ');
	for (register uint64_t i = 0; i < data->size(); ++i) {
		s[2 * i] = hexmap[((*data)[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[(*data)[i] & 0x0F];
	}
	return s;
};

pair<string, string> ECDSA_PrimeField::CreateDigitalSign(const string& d, const string& Message){
	//Create Elliptic Curve Point G
	ECPoint _G(this);
	_G._x = _Gx;
	_G._y = _Gy;
		
	bigint _d;
	_d.FromString(d, 10);
	_d %= _n;
	_d = _d < 0 ? _d + _n : _d;
	
	//STEP 1
	SHA512 HashCalculateObject;
	
	//vector<uint8_t> _Message(Message.begin(), Message.end());

	vector<uint8_t>* _MessageDigest;
	_MessageDigest = HashCalculateObject.GetHash(&vector<uint8_t>(Message.begin(), Message.end()));

	//STEP 2
	bigint _Alpha;
	_Alpha.FromString(hexStr(_MessageDigest), 16);
	delete _MessageDigest;

	bigint e = _Alpha % _n;
	e = (e < 0 ? e + _n : e);
	e = (e == 0 ? 1 : e);
	
	bigint r = 0;
	bigint s = 0;
	bigint k;
	while (s == 0) {
		while (r == 0) {
			//STEP 3
			//Generate PRN k : 0 < k < n
			CSPRNG generatorPRNG;
			vector<uint8_t>* byarrPRN;
			byarrPRN = generatorPRNG.GeneratePRN(256);

			//PRN k in bigint format
			k.FromString(hexStr(byarrPRN), 16);
			delete byarrPRN;

			k %= _n;
			k = k < 0 ? k + _n : k;

			//STEP 4
			//Create Elliptic Curve Point C
			ECPoint C(this);
			C = _G*k;

			//Calculate r = Xc(mod q), where Xc - 'x' coordinate of Elliptic Curve C
			r = C._x % _n;
			r = r < 0 ? r + _n : r;
		}

		//STEP 5
		s = (r*_d + k*e) % _n;
		s = s < 0 ? s + _n : s;
	}

	//STEP 6
	//Create Digital Sign
	return pair<string, string>(r.ToString(), s.ToString());
};

bool ECDSA_PrimeField::CheckDigitalSign(const pair<string, string>& DigitalSign, const string& Message, const pair<string, string>& Q){
	bigint r;
	bigint s;
	r.FromString(DigitalSign.first, 10);
	s.FromString(DigitalSign.second, 10);

	ECPoint _G(this);
	_G._x = _Gx;
	_G._y = _Gy;

	ECPoint _Q(this);
	_Q.setCoordinate(Q.first, Q.second);

	//STEP 1
	if (!((r > 0 && r < _n) && (s > 0 && s < _n))) { return false; }

	//STEP 2
	SHA512 HashCalculateObject;

	vector<uint8_t> _Message(Message.begin(), Message.end());

	vector<uint8_t>* _MessageDigest;
	_MessageDigest = HashCalculateObject.GetHash(&_Message);

	//STEP 3
	bigint _Alpha;
	_Alpha.FromString(hexStr(_MessageDigest), 16);
	delete _MessageDigest;

	bigint e = _Alpha % _n;
	e = (e < 0 ? e + _n : e);
	e = (e == 0 ? 1 : e);

	//STEP 4
	bigint v = ECPoint::ReverseElementInField(e, _n);

	//STEP 5
	bigint z1 = (s*v) % _n;
	z1 = z1 < 0 ? z1 + _n : z1;

	bigint z2 = (-r*v % _n);
	z2 = z2 < 0 ? z2 + _n : z2;

	//STEP 6
	ECPoint C(this);
	C = _G*z1 + _Q*z2;

	bigint R = C._x % _n;
	R = R < 0 ? R + _n : R;

	if (R != r) { return false; }

	return true;
};

pair<string, string> ECDSA_PrimeField::CreateKeyCheckDigitalSign(const string& d){
	bigint _d;
	_d.FromString(d, 10);
	_d %= _n;
	_d = _d < 0 ? _d + _n : _d;

	ECPoint _G(this);
	_G._x = _Gx;
	_G._y = _Gy;

	ECPoint _Q(this);	
	_Q = _G*_d;
	return pair<string, string>(_Q._x.ToString(), _Q._y.ToString());
};

pair<string, string> ECDSA_PrimeField::MultiplyOnBasePoint(const bigint& Number){
	bigint _d(Number);
	//Check that 0 < _d < n
	_d %= _n;
	_d = _d < 0 ? _d + _n : _d;

	//Create Elliptic Curve Point G
	ECPoint _G(this);
	_G._x = _Gx;
	_G._y = _Gy;

	ECPoint _Q(this);
	_Q = _G*_d;
	return pair<string, string>(_Q._x.ToString(), _Q._y.ToString());
};

ECDSA_PrimeField::ECDSA_PrimeField(bigint& a, bigint& b, bigint& p, bigint& Gx, bigint& Gy, bigint& n){
	_a = a;
	_b = b;
	_p = p;
	_Gx = Gx;
	_Gy = Gy;
	_n = n;
};

ECDSA_PrimeField::~ECDSA_PrimeField(){
	return;
};
/*End ECDSA_PrimeField Methods*/
