#pragma once

/*
GOST 34.12-2018 (CIPHER KUZNECHIK ALGORITHM)
CATEGORY: COMPUTER SECURITY SUBCATEGORY: CRYPTOGRAPHY
RUSSIAN TECHNOLOGICAL UNIVERSITY [RTU MIREA]
*/

#include <iostream>
#include <cstring>
#include <vector>
#include <memory>

using namespace std;


class KUZNECHIK {
private:
	/*POINTER TO ARRAY OF KEY*/
	vector<uint8_t>* Key;

	/*POINTER TO ARRAY FOR ROUND KEYS*/
	vector<vector<uint8_t>>* K;


	/*X TRANSFORMATION*/
	void X_transformation(vector<uint8_t>* a, vector<uint8_t>* k);

	/*NON LINEAR BIECTIV TRANSFORMATION*/
	void S_transformation(vector<uint8_t>* a);

	void Inv_S_transformation(vector<uint8_t>* a);

	/*LINEAR TRANSFORMATION*/
	uint8_t l_transformation(vector<uint8_t>* a);

	void R_transformation(vector<uint8_t>* a);

	void L_transformation(vector<uint8_t>* a);

	void Inv_R_transformation(vector<uint8_t>* a);

	void Inv_L_transformation(vector<uint8_t>* a);

	/*F TRANSFORMATION*/
	void F_transformation(vector<uint8_t>* k, vector<uint8_t>* a1, vector<uint8_t>* a0);

	/*KEY EXPANSION ALGORITHM*/
	void KeyExpansion();

public:
	KUZNECHIK();

	~KUZNECHIK();

	/*ENCRYPTION BLOCK*/
	vector<uint8_t> EncryptionBlock(vector<uint8_t>* arrbyBlockPlainText, vector<uint8_t>* byarrKey);

	/*DECRYPTION BLOCK*/
	vector<uint8_t> KUZNECHIK::DecryptionBlock(vector<uint8_t>* arrbyBlockCipherText, vector<uint8_t>* byarrKey);
};