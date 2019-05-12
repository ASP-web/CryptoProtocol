#include "AES.h"
#include "AES.h"

/*Start InterfaceAES Methods Realization*/
void IAES::SetEncryptionMode(uint8_t EncryptionModeID){
	switch (EncryptionModeID) {
	//EncryptionModeID = '0' is ECB mode
	case 0: {
		delete _pEncryptionMode;
		_pEncryptionMode = new ECB(_pRijndael);
		break;
	}
	//EncryptionModeID = '1' is CTR mode
	case 1: {
		delete _pEncryptionMode;
		_pEncryptionMode = new CTR(_pRijndael);
		break;
	}
	//EncryptionModeID = '2' is OFB mode
	case 2: {
		delete _pEncryptionMode;
		_pEncryptionMode = new OFB(_pRijndael);
		break;
	}
	default: break;
	}
}
/*End InterfaceAES Methods Realization*/


/*Start AES 128 Methods Realization*/
vector<uint8_t>* AES_128::Encrypt(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey) {
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 16 == 0)) {
		return _pEncryptionMode->Encryption(byarrBufferPlainText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_128::Decrypt(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 16 == 0)) {
		return _pEncryptionMode->Decryption(byarrBufferCipherText, byarrKey);
	}
	else {
		return nullptr;
	}
}
/*End AES 128 Methods Realization*/


/*Start AES 192 Methods Realization*/
vector<uint8_t>* AES_192::Encrypt(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 24 == 0)) {
		return _pEncryptionMode->Encryption(byarrBufferPlainText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_192::Decrypt(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 24 == 0)) {
		return _pEncryptionMode->Decryption(byarrBufferCipherText, byarrKey);
	}
	else {
		return nullptr;
	}
}
/*End AES 192 Methods Realization*/


/*Start AES 256 Methods Realization*/
vector<uint8_t>* AES_256::Encrypt(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey) {
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 32 == 0)) {
		return _pEncryptionMode->Encryption(byarrBufferPlainText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_256::Decrypt(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey) {
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 32 == 0)) {
		return _pEncryptionMode->Decryption(byarrBufferCipherText, byarrKey);
	}
	else {
		return nullptr;
	}
}
/*End AES 256 Methods Realization*/