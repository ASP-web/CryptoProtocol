#ifndef ENCRYPTIONMODE_H
#define ENCRYPTIONMODE_H

#include "Rijndael.h"
#include <thread>

using namespace std;

/*Interface Encryption Mode Class*/
class IEncryptionMode {
protected:
	Rijndael* _pRijndael{ nullptr };
public:
	IEncryptionMode(Rijndael* pRijndael) : _pRijndael(pRijndael) {};
	
	virtual vector<uint8_t>* Encryption(vector<uint8_t>* PlainText, vector<uint8_t>* Key) = 0;
	
	virtual vector<uint8_t>* Decryption(std::vector<uint8_t>* CipherText, vector<uint8_t>* Key) = 0;
	
	void AdditionBlocksRatio(vector<uint8_t>* arrbyBufferPublicText);
};

/*ECB Encryption Mode Class*/
class ECB : public IEncryptionMode {
private:
	/*Realization Multi threading*/
	void ThreadEncription(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock);

	void ThreadDecryption(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock);

public:
	ECB(Rijndael* pRijndael) : IEncryptionMode(pRijndael) {};

	vector<uint8_t>* Encryption(vector<uint8_t>* PlainText, vector<uint8_t>* Key) override;

	vector<uint8_t>* Decryption(vector<uint8_t>* CipherText, vector<uint8_t>* Key) override;
};

/*CTR Encryption Mode Class*/
class CTR : public IEncryptionMode {
private:
	/*Realization Multi threading*/
	void ThreadEncription(vector<uint8_t> IV, vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock);

	void ThreadDecryption(vector<uint8_t> _IV, vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock);

public:
	CTR(Rijndael* pRijndael) : IEncryptionMode(pRijndael) {};

	vector<uint8_t>* Encryption(vector<uint8_t>* PlainText, vector<uint8_t>* Key) override;

	vector<uint8_t>* Decryption(vector<uint8_t>* CipherText, vector<uint8_t>* Key) override;
};

/*OFB Encryption Mode Class*/
class OFB : public IEncryptionMode {
public:
	OFB(Rijndael* pRijndael) : IEncryptionMode(pRijndael) {};

	vector<uint8_t>* Encryption(vector<uint8_t>* PlainText, vector<uint8_t>* Key) override;

	vector<uint8_t>* Decryption(vector<uint8_t>* CipherText, vector<uint8_t>* Key) override;
};


#endif //ENCRYPTIONMODE_h
