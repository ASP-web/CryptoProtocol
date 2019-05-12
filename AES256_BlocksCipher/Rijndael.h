#ifndef RIJNDAEL_H
#define RIJNDAEL_H

/*
Federal Information
Processing Standards Publication 197
November 26, 2001
Announcing the
ADVANCED ENCRYPTION STANDARD (AES)

RUSSIAN TECHNOLOGICAL UNIVERSITY [RTU MIREA]
REALIZATION Rijndael Algorithm Block Cipher
*/

#include <iostream>
#include <string>
#include <vector>
#include <iterator>

using namespace std;

class Rijndael {
private:
	uint8_t Nb{ 0 };					// number of rows in Matrix State, in standard FIPS197 this value is 4
	uint8_t Nk{ 0 };					// key length variable
	uint8_t Nr{ 0 };					// nuMber of rounds
						
	vector<uint8_t>* Key;				// array of Key	
	vector<uint8_t>* RoundKeys;			// array of RoundKeys
	//vector<vector<uint8_t>>* State;		// matrix of State

	/*Crypt Functions*/

	void SubBytes(vector<vector<uint8_t>>* State);
	
	void ShiftRows(vector<vector<uint8_t>>* State);

	void MixColomns(vector<vector<uint8_t>>* State);

	void AddRoundKey(uint8_t byCurrentRound, vector<vector<uint8_t>>* State);

	void KeyExpansion();

	/*Decrypt Function*/

	void InvShiftRows(vector<vector<uint8_t>>* State);

	void InvSubBytes(vector<vector<uint8_t>>* State);

	void InvMixColomns(vector<vector<uint8_t>>* State);

public:
	
	vector<uint8_t> Encrypt(vector<uint8_t>& arrbyBlockPlainText, vector<uint8_t>* byarrKey);

	vector<uint8_t> Decrypt(vector<uint8_t>& arrbyBlockCipherText, vector<uint8_t>* byarrKey);

	Rijndael(uint8_t, uint8_t, uint8_t);

	Rijndael() : Rijndael(4, 4, 10) {};

	~Rijndael();
};

#endif //RIJNDAEL_H
