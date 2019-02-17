#include "AES.h"
#include "AES.h"

vector<uint8_t>* AES_128::Encrypt(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey) {
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 16 == 0)) {
		return this->Rijndael::Encrypt(byarrBufferPlainText, byarrKey);
	}
	else{
		return nullptr;
	}
}

vector<uint8_t>* AES_128::Decrypt(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 16 == 0)) {
		return Rijndael::Decrypt(byarrBufferCipherText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_192::Encrypt(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 24 == 0)) {
		return Rijndael::Encrypt(byarrBufferPlainText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_192::Decrypt(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 24 == 0)) {
		return Rijndael::Decrypt(byarrBufferCipherText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_256::Encrypt(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 32 == 0)) {
		return Rijndael::Encrypt(byarrBufferPlainText, byarrKey);
	}
	else {
		return nullptr;
	}
}

vector<uint8_t>* AES_256::Decrypt(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey){
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 32 == 0)) {
		return Rijndael::Decrypt(byarrBufferCipherText, byarrKey);
	}
	else {
		return nullptr;
	}
}
