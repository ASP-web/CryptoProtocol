#ifndef TEST_CSPRNG_H
#define TEST_CSPRNG_H

#include "../CSPRNG/CSPRNG.h"
#include "gtest/gtest.h"
#include <fstream>
#include <chrono>

using namespace std;

class TestCSPRNG : public ::testing::Test {
public:
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;
};
//
//TEST_F(TestCSPRNG, CorrectWorkGenerate_8bytes) {
//	CSPRNG generator;
//	vector<uint8_t>* PRNG = generator.GeneratePRN(8);
//	ofstream FileOutput;
//	FileOutput.open("gen.txt", ios::binary, ios::trunc);
//	for (unsigned char i : *PRNG) { FileOutput.put(i); }
//	FileOutput.close();
//	ASSERT_EQ(PRNG->size(), 8);
//	delete PRNG;
//}

TEST_F(TestCSPRNG, CorrectWorkGenerate_10Mbyte) {
	CSPRNG generator;

	start = myclock::now();
	vector<uint8_t>* PRNG = generator.GeneratePRN(10485760);
	end = myclock::now();
	cout << "10 Mbyte PRN Generation time: " << chrono::duration_cast<chrono::microseconds>(end - start).count() << " microseconds" << endl;

	ofstream FileOutput;
	FileOutput.open("gen.txt", ios::binary, ios::trunc);
	for (unsigned char i : *PRNG){ FileOutput.put(i); }
	FileOutput.close();
	ASSERT_EQ(PRNG->size(), 10485760);
	delete PRNG;
}


#endif //TEST_CSPRNG_H