#include "Rijndael.h"
#include "Tables.h"

#include <iostream>

using namespace std;

void Rijndael::SubBytes(vector<vector<uint8_t>>* State){
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { (*State)[j][i] = Sbox[(*State)[j][i]]; }
	}
};

void Rijndael::ShiftRows(vector<vector<uint8_t>>* State){
	//Shift 1 row
	swap((*State)[0][1], (*State)[3][1]);
	swap((*State)[0][1], (*State)[1][1]);
	swap((*State)[1][1], (*State)[2][1]);
	//Shift 2 row
	swap((*State)[0][2], (*State)[2][2]);
	swap((*State)[1][2], (*State)[3][2]);
	//Shift 3 row
	swap((*State)[0][3], (*State)[3][3]);
	swap((*State)[1][3], (*State)[3][3]);
	swap((*State)[2][3], (*State)[3][3]);
};

void Rijndael::MixColomns(vector<vector<uint8_t>>* State){
	vector<vector<uint8_t>> TempState(*State);
	//MixColoms 0,1,2,3; Callc Cells in Colomn[i]
	for (uint8_t i = 0; i < 4; i++) {
		(*State)[i][0] = mul0x02[TempState[i][0]] ^ mul0x03[TempState[i][1]] ^ TempState[i][2] ^ TempState[i][3];
		(*State)[i][1] = TempState[i][0] ^ mul0x02[TempState[i][1]] ^ mul0x03[TempState[i][2]] ^ TempState[i][3];
		(*State)[i][2] = TempState[i][0] ^ TempState[i][1] ^ mul0x02[TempState[i][2]] ^ mul0x03[TempState[i][3]];
		(*State)[i][3] = mul0x03[TempState[i][0]] ^ TempState[i][1] ^ TempState[i][2] ^ mul0x02[TempState[i][3]];
	}
	TempState.clear();
};

void Rijndael::AddRoundKey(uint8_t byCurrentRound, vector<vector<uint8_t>>* State){
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { (*State)[i][j] ^= (*RoundKeys)[byCurrentRound * Nb * Nb + i * Nb + j]; }
	}
};

void Rijndael::KeyExpansion(){
	for (uint8_t i = 0; i < Nk; i++) {
		(*RoundKeys)[i * Nb] = (*Key)[i * 4];
		(*RoundKeys)[i * Nb + 1] = (*Key)[i * Nb + 1];
		(*RoundKeys)[i * Nb + 2] = (*Key)[i * Nb + 2];
		(*RoundKeys)[i * Nb + 3] = (*Key)[i * Nb + 3];
	}

	uint8_t i = Nk, byarrWord[4];

	while (i < (Nb*(Nr+1))){
		for (uint8_t j = 0; j < 4; j++) { byarrWord[j] = (*RoundKeys)[(i - 1) * Nb + j]; }
		if (i%Nk == 0) {	
			//RotWord Function
			{
				swap(byarrWord[0], byarrWord[3]);
				swap(byarrWord[0], byarrWord[1]);
				swap(byarrWord[1], byarrWord[2]);
			}
			//SubWord Function
			{
				byarrWord[0] = Sbox[byarrWord[0]];
				byarrWord[1] = Sbox[byarrWord[1]];
				byarrWord[2] = Sbox[byarrWord[2]];
				byarrWord[3] = Sbox[byarrWord[3]];
			}
			byarrWord[0] = byarrWord[0] ^ Rcon[i / Nk];
		}
		else if ((Nk > 6) && (i%Nk == 4)) {
			//SubWord Function
			{
				byarrWord[0] = Sbox[byarrWord[0]];
				byarrWord[1] = Sbox[byarrWord[1]];
				byarrWord[2] = Sbox[byarrWord[2]];
				byarrWord[3] = Sbox[byarrWord[3]];
			}
		}
		(*RoundKeys)[i * Nb + 0] = (*RoundKeys)[(i - Nk) * Nb + 0] ^ byarrWord[0];
		(*RoundKeys)[i * Nb + 1] = (*RoundKeys)[(i - Nk) * Nb + 1] ^ byarrWord[1];
		(*RoundKeys)[i * Nb + 2] = (*RoundKeys)[(i - Nk) * Nb + 2] ^ byarrWord[2];
		(*RoundKeys)[i * Nb + 3] = (*RoundKeys)[(i - Nk) * Nb + 3] ^ byarrWord[3];
		i++;
	}
};

void Rijndael::InvShiftRows(vector<vector<uint8_t>>* State){
	//Shift 1 row
	swap((*State)[0][1], (*State)[3][1]);
	swap((*State)[3][1], (*State)[1][1]);
	swap((*State)[3][1], (*State)[2][1]);
	//Shift 2 row
	swap((*State)[0][2], (*State)[2][2]);
	swap((*State)[1][2], (*State)[3][2]);
	//Shift 3 row
	swap((*State)[0][3], (*State)[3][3]);
	swap((*State)[0][3], (*State)[1][3]);
	swap((*State)[2][3], (*State)[1][3]);
};

void Rijndael::InvSubBytes(vector<vector<uint8_t>>* State){
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { (*State)[j][i] = InvSbox[(*State)[j][i]]; }
	}
};

void Rijndael::InvMixColomns(vector<vector<uint8_t>>* State){
	vector<vector<uint8_t>> TempState(*State);
	//InvMixColoms 0,1,2,3; Callc Cells in Colomn[i]
	for (uint8_t i = 0; i < 4; i++) {
		(*State)[i][0] = mul0x0e[TempState[i][0]] ^ mul0x0b[TempState[i][1]] ^ mul0x0d[TempState[i][2]] ^ mul0x09[TempState[i][3]];
		(*State)[i][1] = mul0x09[TempState[i][0]] ^ mul0x0e[TempState[i][1]] ^ mul0x0b[TempState[i][2]] ^ mul0x0d[TempState[i][3]];
		(*State)[i][2] = mul0x0d[TempState[i][0]] ^ mul0x09[TempState[i][1]] ^ mul0x0e[TempState[i][2]] ^ mul0x0b[TempState[i][3]];
		(*State)[i][3] = mul0x0b[TempState[i][0]] ^ mul0x0d[TempState[i][1]] ^ mul0x09[TempState[i][2]] ^ mul0x0e[TempState[i][3]];
	}
	TempState.clear();
};

vector<uint8_t> Rijndael::Encrypt(vector<uint8_t>& arrbyBlockPlainText, vector<uint8_t>* byarrKey){
	//Create matrix State with size 4*Nb and Value in Cells is 0
	auto State = new vector<vector<uint8_t>>(Nb, vector<uint8_t>(Nb, 0));

	//Expansion Work Key
	if (Key != byarrKey) { 
		Key = byarrKey;
		KeyExpansion(); 
	}

	//Create Buffer Block Cipher Text
	vector<uint8_t> arrbyBlockCipherText;

	//Add OT Block in State
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) {
			(*State)[i][j] = arrbyBlockPlainText[i * Nb + j];
		}
	}		
	//Round {0}
	AddRoundKey(0, State);
	//Rounds {1, 2, 3, ..., 9} or {1, 2, 3, ..., 11} or {1, 2, 3, ..., 13}
	for (uint8_t byCurrentRound = 1; byCurrentRound < Nr; byCurrentRound++) {
		SubBytes(State);
		ShiftRows(State);
		MixColomns(State);
		AddRoundKey(byCurrentRound, State);
	}
	//Last Round {10} or {12} or {14}
	SubBytes(State);
	ShiftRows(State);
	AddRoundKey(Nr, State);
	//Write CipherTextBlock in arrbyBufferCipherText
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { arrbyBlockCipherText.push_back((*State)[i][j]); }
	}

	delete State;
	return arrbyBlockCipherText;
};

vector<uint8_t> Rijndael::Decrypt(vector<uint8_t>& arrbyBlockCipherText, vector<uint8_t>* byarrKey){
	//Create matrix State with size 4*Nb and Value in Cells is 0
	auto State = new vector<vector<uint8_t>>(Nb, vector<uint8_t>(Nb, 0));

	//Expansion Work Key
	if (Key != byarrKey) {
		Key = byarrKey;
		KeyExpansion();
	}

	//Create Buffer Block Plain Text
	vector<uint8_t> arrBlockPlainText;

	//Add OT Block in State
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) {
			(*State)[i][j] = arrbyBlockCipherText[i * Nb + j];
		}
	}
	//Round {0}
	AddRoundKey(Nr, State);
	//Rounds {1, 2, 3, ..., 9} or {1, 2, 3, ..., 11} or {1, 2, 3, ..., 13}
	for (uint8_t byCurrentRound = Nr - 1; byCurrentRound > 0; byCurrentRound--) {
		InvShiftRows(State);
		InvSubBytes(State);
		AddRoundKey(byCurrentRound, State);
		InvMixColomns(State);
	}
	//Last Round {10} or {12} or {14}
	InvSubBytes(State);
	InvShiftRows(State);
	AddRoundKey(0, State);
	//Write CipherTextBlock in arrbyBufferCipherText
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { arrBlockPlainText.push_back((*State)[i][j]); }
	}
	
	delete State;
	return arrBlockPlainText;
};

Rijndael::Rijndael(uint8_t valueNb, uint8_t valueNk, uint8_t valueNr) {
	Nb = valueNb;
	Nk = valueNk;
	Nr = valueNr;
	RoundKeys = new vector<uint8_t>((Nb*(Nr + 1)*Nb), 0);				//create buffer of RoundKeys size Nb*(Nr+1)*Nb and Value in Cells is 0
};

Rijndael::~Rijndael() {
	memset(RoundKeys->data(), 0x00, RoundKeys->size());					//Security Clear buffer RoundKeys
	delete RoundKeys;
};