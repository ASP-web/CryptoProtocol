#ifndef SHA1_H
#define SHA1_H

/*
			FIPS PUB 180-4
FEDERAL INFORMATION PROCESSING STANDARDS
			  PUBLICATION
		Secure Hash Standard (SHS)
CATEGORY: COMPUTER SECURITY SUBCATEGORY: CRYPTOGRAPHY

	RUSSIAN TECHNOLOGICAL UNIVERSITY [RTU MIREA]
		REALIZATION SHA1 HASH FUNCTION
*/

#include <iostream>
#include <cstring>
#include <vector>
#include <memory>

using namespace std;

class SHA1 {
public:
	const uint32_t K0{ 0x5a827999 };
	const uint32_t K1{ 0x6ed9eba1 };
	const uint32_t K2{ 0x8f1bbcdc };
	const uint32_t K3{ 0xca62c1d6 };

	uint32_t H0{ 0 };
	uint32_t H1{ 0 };
	uint32_t H2{ 0 };
	uint32_t H3{ 0 };
	uint32_t H4{ 0 };

	vector<uint8_t>* byarrMessage{ nullptr };

	unique_ptr<vector<uint32_t>> W{ nullptr };
	unique_ptr<vector<uint32_t>> M{ nullptr };

	void PaddingTheMessage();

	void Preprocessing();

	void HashCompulation();

	void HashComplulationBlock();

	uint32_t ROTL(uint32_t x, uint8_t n);

public:

	vector<uint8_t>* GetHash(vector<uint8_t>* ptrMessage);
};

#endif //SHA1_H
