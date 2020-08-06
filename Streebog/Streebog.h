#pragma once

/*
GOST 34.11-2018 STREEBOG HASH ALGORITHM
CATEGORY: COMPUTER SECURITY SUBCATEGORY: CRYPTOGRAPHY
RUSSIAN TECHNOLOGICAL UNIVERSITY [RTU MIREA]
*/

#include <iostream>
#include <cstring>
#include <vector>
#include <memory>

using namespace std;


class STREEBOG {
private:

	//FIELDS OF CLASS STREEBOG
	unique_ptr<vector<uint64_t>> h{ nullptr };

	unique_ptr<vector<uint64_t>> N{ nullptr };

	unique_ptr<vector<uint64_t>> SIGMA{ nullptr };

	//METHODS OF CLASS STREEBOG
	void X_transformation(vector<uint64_t>* a, const vector<uint64_t>& k);

	void S_transformation(vector<uint64_t>* a);

	void P_transformation(vector<uint64_t>* a);

	void L_transformation(vector<uint64_t>* a);
	
	void gN_CompressFunction(vector<uint64_t>* m);

	void AddModulo512(const uint64_t* a, const uint64_t* b, uint64_t* c);

	void HashCompulation(vector<uint8_t>* ptrMessage, uint64_t sizeMessage);

	void HashCompulationLastBlock(vector<uint8_t>* ptrMessage, uint64_t sizeMessage);

public:

	vector<uint8_t>* GetHash(vector<uint8_t>* ptrMessage);
};

