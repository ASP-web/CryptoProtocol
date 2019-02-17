#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <iostream>
#include <string>
#include <vector>
#include <iterator>

using namespace std;

class Rijndael {
private:
	uint8_t Nb{ 0 };					// number of rows in Matrix State, in standart FIPS197 this value is 4
	uint8_t Nk{ 0 };					// key legth variable
	uint8_t Nr{ 0 };					// nuber of rounds
						
	vector<uint8_t>* Key;				// array of Key	
	vector<uint8_t>* RoundKeys;			// array of RoundKeys
	vector<vector<uint8_t>>* State;		// matrix of State

	/*Crypt Functions*/

	void SubBytes();
	
	void ShiftRows();

	void MixColomns();

	void AddRoundKey(uint8_t);

	void KeyExpansion();

	void AdditionBlocksRatio(vector<uint8_t>*);

	/*Decrypt Function*/

	void InvShiftRows();

	void InvSubBytes();

	void InvMixColomns();

public:
	
	vector<uint8_t>* Encrypt(vector<uint8_t>*, vector<uint8_t>*);

	vector<uint8_t>* Decrypt(vector<uint8_t>*, vector<uint8_t>*);

	Rijndael(uint8_t, uint8_t, uint8_t);

	Rijndael() : Rijndael(4, 4, 10) {};

	~Rijndael();
};

#endif //RIJNDAEL_H
