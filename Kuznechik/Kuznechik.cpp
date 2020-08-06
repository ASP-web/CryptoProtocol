#include "Kuznechik.h"
#include "Tables.h"

/*X TRANSFORMATION*/
void KUZNECHIK::X_transformation(vector<uint8_t>* a, vector<uint8_t>* k) {
	for (uint8_t i = 0; i < a->size(); i++) { (*a)[i] ^= (*k)[i]; }
};

/*NON LINEAR BIECTIV TRANSFORMATION*/
void KUZNECHIK::S_transformation(vector<uint8_t>* a) {
	for (unsigned char & i : *a) { i = PI[i]; }
};

void KUZNECHIK::Inv_S_transformation(vector<uint8_t>* a) {
	for (unsigned char & i : *a) { i = Inv_PI[i]; }
};

/*LINEAR TRANSFORMATION*/
uint8_t KUZNECHIK::l_transformation(vector<uint8_t>* a) { return  
	mul0x94[(*a)[15]] ^ mul0x20[(*a)[14]] ^ mul0x85[(*a)[13]] ^ mul0x10[(*a)[12]] ^
	mul0xc2[(*a)[11]] ^ mul0xc0[(*a)[10]] ^ mul0x1[(*a)[9]] ^ mul0xfb[(*a)[8]] ^
	mul0x1[(*a)[7]] ^ mul0xc0[(*a)[6]] ^ mul0xc2[(*a)[5]] ^ mul0x10[(*a)[4]] ^
	mul0x85[(*a)[3]] ^ mul0x20[(*a)[2]] ^ mul0x94[(*a)[1]] ^ mul0x1[(*a)[0]];
};

void KUZNECHIK::R_transformation(vector<uint8_t>* a) {
	uint8_t l = l_transformation(a);
	for (uint8_t i = 0; i < a->size() - 1; i++) { (*a)[i] = (*a)[i + 1]; }
	(*a)[a->size() - 1] = l;
};

void KUZNECHIK::L_transformation(vector<uint8_t>* a) { 
	for (uint8_t i = 0; i < 16; i++) { R_transformation(a); } 
};

void KUZNECHIK::Inv_R_transformation(vector<uint8_t>* a) {
	for (uint8_t i = 0; i < a->size() - 1; i++) { swap((*a)[i], (*a)[a->size() - 1]); }
	uint8_t l = l_transformation(a);
	(*a)[0] = l;
};

void KUZNECHIK::Inv_L_transformation(vector<uint8_t>* a) {
	for (uint8_t i = 0; i < 16; i++) { Inv_R_transformation(a); }
};

/*F TRANSFORMATION*/
void KUZNECHIK::F_transformation(vector<uint8_t>* k, vector<uint8_t>* a1, vector<uint8_t>* a0) {
	auto temp_a1 =  new vector<uint8_t>(*a1);
	X_transformation(temp_a1, k);
	S_transformation(temp_a1);
	L_transformation(temp_a1);
	for (uint8_t i = 0; i < a0->size(); i++) { (*temp_a1)[i] ^= (*a0)[i]; }
	*a0 = *a1;
	*a1 = *temp_a1;
	delete temp_a1;
};

/*KEY EXPANSION ALGORITHM*/
void KUZNECHIK::KeyExpansion() {
	(*K)[0].insert((*K)[0].begin(), Key->begin() + 16, Key->end());
	(*K)[1].insert((*K)[1].begin(), Key->begin(), Key->begin() + 16);
	for (uint8_t i = 0; i < 4; i++) {
		(*K)[2 * i + 2] = (*K)[2 * i];
		(*K)[2 * i + 3] = (*K)[2 * i + 1];
		for (uint8_t j = 0; j < 8; j++) { F_transformation(const_cast<vector<uint8_t>*>(&C[8 * i + j]), &(*K)[2 * i + 2], &(*K)[2 * i + 3]); }
	}
};

/*ENCRYPTION BLOCK*/
vector<uint8_t> KUZNECHIK::EncryptionBlock(vector<uint8_t>* arrbyBlockPlainText, vector<uint8_t>* byarrKey) {
	vector<uint8_t> a(*arrbyBlockPlainText);
	//Expansion Work Key
	if (Key != byarrKey) {
		Key = byarrKey;
		KeyExpansion();
	}
	//ROUNDS 1, 2, 3,..., 9
	for (uint8_t i = 0; i < 9; i++) {
		X_transformation(&a, &(*K)[i]);
		S_transformation(&a);
		L_transformation(&a);
	}
	//LAST ROUND 10
	X_transformation(&a, &(*K)[9]);
	return a;
};

/*DECRYPTION BLOCK*/
vector<uint8_t> KUZNECHIK::DecryptionBlock(vector<uint8_t>* arrbyBlockCipherText, vector<uint8_t>* byarrKey) {
	vector<uint8_t> a(*arrbyBlockCipherText);
	//Expansion Work Key
	if (Key != byarrKey) {
		Key = byarrKey;
		KeyExpansion();
	}
	//ROUNDS 10, 9, 8,..., 2 
	for (uint8_t i = 9; i > 0; i--) {
		X_transformation(&a, &(*K)[i]);
		Inv_L_transformation(&a);
		Inv_S_transformation(&a);
	}
	//LAST ROUND 1
	X_transformation(&a, &(*K)[0]);
	return a;
}

/*CONSTRUCTOR*/
KUZNECHIK::KUZNECHIK() { K = new vector<vector<uint8_t>>(10); };

/*DESTRUCTOR*/
KUZNECHIK::~KUZNECHIK() { 
	for (auto & i : *K) { memset(i.data(), 0x00, i.size()); }  //SECURITY CLEAR ROUND KEYS ARRAY
	Key = nullptr;
};  
