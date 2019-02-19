// main.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
//#include "Test_Rijndael.h"
//#include "Test_AES.h"
#include "Test_SHA1.h"

using namespace std;

int main(int argc, char* argv[]){
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}