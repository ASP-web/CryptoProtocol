#include "Rijndael.h"
#include "Tables.h"

#include <iostream>

using namespace std;

void Rijndael::SubBytes(){
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { (*State)[j][i] = Sbox[(*State)[j][i]]; }
	}
};

void Rijndael::ShiftRows(){
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

void Rijndael::MixColomns(){
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

void Rijndael::AddRoundKey(uint8_t byCurrentRound){
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

void Rijndael::AdditionBlocksRatio(vector<uint8_t>* arrbyBufferPublicText){
	//Work by GOST 34.12-2015
	arrbyBufferPublicText->push_back(0x80);
	for (uint8_t i = 0; i < (arrbyBufferPublicText->size() % 16); i++) { arrbyBufferPublicText->push_back(0x00); }
};

void Rijndael::InvShiftRows(){
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

void Rijndael::InvSubBytes(){
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 4; j++) { (*State)[j][i] = InvSbox[(*State)[j][i]]; }
	}
};

void Rijndael::InvMixColomns(){
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

vector<uint8_t>* Rijndael::Encrypt(vector<uint8_t>* arrbyBufferPlainText, vector<uint8_t>* byarrKey){
	Key = byarrKey;
	//Expansion Work Key
	KeyExpansion();
	//Check AdditionBlockRatio
	if (arrbyBufferPlainText->size() % 16 != 0) { AdditionBlocksRatio(arrbyBufferPlainText); }
	
	vector<uint8_t>* arrbyBufferCipherText = new vector<uint8_t>;
	for (uint32_t dwCurrentBlock = 0; dwCurrentBlock < (arrbyBufferPlainText->size() / 16); dwCurrentBlock++) {
		//Add OT Block in State
		for (uint8_t i = 0; i < 4; i++) {
			for (uint8_t j = 0; j < 4; j++) {
				(*State)[i][j] = (*arrbyBufferPlainText)[dwCurrentBlock * Nb * Nb + i * Nb + j];
			}
		}		
		//Round {0}
		AddRoundKey(0);
		//Rounds {1, 2, 3, ..., 9} or {1, 2, 3, ..., 11} or {1, 2, 3, ..., 13}
		for (uint8_t byCurrentRound = 1; byCurrentRound < Nr; byCurrentRound++) {
			SubBytes();
			ShiftRows();
			MixColomns();
			AddRoundKey(byCurrentRound);
		}
		//Last Round {10} or {12} or {14}
		SubBytes();
		ShiftRows();
		AddRoundKey(Nr);
		//Write CipherTextBlock in arrbyBufferCipherText
		for (uint8_t i = 0; i < 4; i++) {
			for (uint8_t j = 0; j < 4; j++) { arrbyBufferCipherText->push_back((*State)[i][j]); }
		}
	}
	return arrbyBufferCipherText;
};

vector<uint8_t>* Rijndael::Decrypt(vector<uint8_t>* arrbyBufferCipherText, vector<uint8_t>* byarrKey){
	Key = byarrKey;
	//Expansion Work Key
	KeyExpansion();

	vector<uint8_t>* arrbyBufferPlainText = new vector<uint8_t>;
	for (uint32_t dwCurrentBlock = 0; dwCurrentBlock < (arrbyBufferCipherText->size() / 16); dwCurrentBlock++) {
		//Add OT Block in State
		for (uint8_t i = 0; i < 4; i++) {
			for (uint8_t j = 0; j < 4; j++) {
				(*State)[i][j] = (*arrbyBufferCipherText)[dwCurrentBlock * Nb * Nb + i * Nb + j];
			}
		}
		//Round {0}
		AddRoundKey(Nr);
		//Rounds {1, 2, 3, ..., 9} or {1, 2, 3, ..., 11} or {1, 2, 3, ..., 13}
		for (uint8_t byCurrentRound = Nr - 1; byCurrentRound > 0; byCurrentRound--) {
			InvShiftRows();
			InvSubBytes();
			AddRoundKey(byCurrentRound);
			InvMixColomns();
		}
		//Last Round {10} or {12} or {14}
		InvSubBytes();
		InvShiftRows();
		AddRoundKey(0);
		//Write CipherTextBlock in arrbyBufferCipherText
		for (uint8_t i = 0; i < 4; i++) {
			for (uint8_t j = 0; j < 4; j++) { arrbyBufferPlainText->push_back((*State)[i][j]); }
		}
	}
	return arrbyBufferPlainText;
};

Rijndael::Rijndael(uint8_t valueNb, uint8_t valueNk, uint8_t valueNr) {
	Nb = valueNb;
	Nk = valueNk;
	Nr = valueNr;
	State = new vector<vector<uint8_t>>(Nb, vector<uint8_t>(Nb,0));		//create matrix State with size 4*Nb and Value in Cells is 0
	RoundKeys = new vector<uint8_t>((Nb*(Nr + 1)*Nb), 0);				//create buffer of RoundKeys size Nb*(Nr+1)*Nb and Value in Cells is 0
};

Rijndael::~Rijndael() {
	delete State;
	memset(RoundKeys->data(), 0x00, RoundKeys->size());					//Security Clear buffer RoundKeys
	delete RoundKeys;
};