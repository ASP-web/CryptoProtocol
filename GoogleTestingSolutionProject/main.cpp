// main.cpp : Defines the entry point for the console application.
//

#define _HAS_EXCEPTIONS 0
//#define _STATIC_CPPLIB

#include "stdafx.h"
//#include "Test_Rijndael.h"
//#include "Test_AES.h"
//#include "Test_SHA1.h"
//#include "Test_SHA512.h"
//#include "Test_ECPoint.h"
//#include "Test_ECDSA_PrimeField.h"
//#include "Test_ECDSA.h"
//#include "Test_CSPRNG.h"
//#include "Test_RSA.h"
//#include "Test_Streebog.h"
#include "Test_Kuznechik.h"

using namespace std;

int main(int argc, char** argv){
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}