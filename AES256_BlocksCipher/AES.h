#ifndef AES_H
#define AES_H

#include "Rijndael.h"

class AES_128 : public Rijndael {
public:
	vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key);
	vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key);
};

class AES_192 : public Rijndael {
public:
	AES_192() : Rijndael(4, 6, 12) {};
	vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key);
	vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key);
};

class AES_256 : public Rijndael {
public:
	AES_256() : Rijndael(4, 8, 14) {};
	vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key);
	vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key);
};


#endif
