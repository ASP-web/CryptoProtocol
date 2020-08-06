#pragma once

#include <iostream>
#include <vector>
#include "../CSPRNG/CSPRNG.h"

#include "ttmath/ttmath.h"
#include "ttmath/ttmathint.h"

#include "Atkin4.h"
#include "Miller-Rabin.h"
#include "BPSW.h"

using namespace std;

using bigint = ttmath::Int<64>;

class RSA {
	CSPRNG generatorPRN;

	//Atkin4 atkin4;
	//Miller_Rabin MillerRabinTest;
	bigint p;
	bigint q;

public:

	string hexStr(vector<uint8_t>* data);

	void GeneratePrimeParametr_p();

	bool isPrime_SmallFermaTeorem(bigint n);
};