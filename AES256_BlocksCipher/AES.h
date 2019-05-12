#ifndef AES_H
#define AES_H

/*
Federal Information
Processing Standards Publication 197
November 26, 2001
Announcing the
ADVANCED ENCRYPTION STANDARD (AES)

RUSSIAN TECHNOLOGICAL UNIVERSITY [RTU MIREA]
REALIZATION AES 128/192/256 Block Cipher
*/

/*
	ANNOTATION:
-> When you are create instance of AES_(128/192/256) the default encryption mode is ECB encryption mode
-> SetEncryptionMode allows change encryption mode in Runtime
-> EncryptionModeId is:
	--> '0' - ECB encryption mode;
	--> '1' - CTR encryption mode;
	--> 'other'	- save previous mode;
->
*/


#include "Rijndael.h"
#include "EncryptionMode.h"

/*Interface class AES*/
class IAES {
protected:
	IEncryptionMode* _pEncryptionMode{ nullptr };
	Rijndael* _pRijndael{ nullptr };
	uint8_t Nb{ 0 };
	uint8_t Nk{ 0 };
	uint8_t Nr{ 0 };
public:
	virtual vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key) = 0;
	virtual vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key) = 0;
	void SetEncryptionMode(uint8_t EncryptionModeID);
};

/*AES 128 Class*/
class AES_128 : public IAES {
public:
	vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key) override;
	vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key) override;

	AES_128() { 
		Nb = 4;
		Nk = 4;
		Nr = 10;
		_pRijndael = new Rijndael(Nb,Nk,Nr); 
		_pEncryptionMode = new ECB(_pRijndael);
	}

	~AES_128() {
		delete _pEncryptionMode;
		delete _pRijndael;
	}
};

/*AES 192 Class*/
class AES_192 : public IAES {
public:
	vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key) override;
	vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key) override;

	AES_192() {
		Nb = 4;
		Nk = 6;
		Nr = 12;
		_pRijndael = new Rijndael(Nb, Nk, Nr);
		_pEncryptionMode = new ECB(_pRijndael);
	} 

	~AES_192() {
		delete _pEncryptionMode;
		delete _pRijndael;
	}
};

/*AES 256 Class*/
class AES_256 : public IAES {
public:
	vector<uint8_t>* Encrypt(vector<uint8_t>* PlainText, vector<uint8_t>* Key) override;
	vector<uint8_t>* Decrypt(vector<uint8_t>* CipherText, vector<uint8_t>* Key) override;

	AES_256() {
		Nb = 4;
		Nk = 8;
		Nr = 14;
		_pRijndael = new Rijndael(Nb, Nk, Nr);
		_pEncryptionMode = new ECB(_pRijndael);
	} 
	
	~AES_256() {
		delete _pEncryptionMode;
		delete _pRijndael;
	}
};

#endif
