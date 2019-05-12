#include "Protocol.h"
#include <openssl/bn.h>
#include <fstream>

const uint8_t hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

User_Alice::User_Alice() : IUser(
	string("protocol/ALICE/RSA/PUBLIC_KEY/PUBLIC_KEY.pem"),
	string("protocol/ALICE/RSA/PRIVATE_KEY/PRIVATE_KEY.pem"),
	string("protocol/ALICE/FROM/CA_SERVER/RSA/SIGN_ALICE_PUBLIC_KEY.sig"),
	string("protocol/ALICE/FROM/CA_SERVER/RSA/PUBLIC_KEY/PUBLIC_KEY.pem"),
	string("protocol/ALICE/FROM/BOB/RSA/PUBLIC_KEY/PUBLIC_KEY.pem"),
	string("protocol/ALICE/FROM/BOB/RSA/SIGN_BOB_PUBLIC_KEY.sig"),

	string("protocol/ALICE/RSA/ECDHE/PUBLIC POINT/EncRSA_Qx.cor"),
	string("protocol/ALICE/RSA/ECDHE/PUBLIC POINT/EncRSA_Qy.cor"),

	string("protocol/ALICE/FROM/BOB/RSA/ECDHE/PUBLIC POINT/EncRSA_Qx.cor"),
	string("protocol/ALICE/FROM/BOB/RSA/ECDHE/PUBLIC POINT/EncRSA_Qy.cor"),
	string("protocol/ALICE/FROM/BOB/ECDHE/PUBLIC POINT/Qx.cor"),
	string("protocol/ALICE/FROM/BOB/ECDHE/PUBLIC POINT/Qy.cor"),

	string("protocol/ALICE/ECDHE/SESSION KEY/SECRET.KEY"),
	string("protocol/ALICE/ECDHE/CHECKER CORRECT/CHECK.SIG"),
	string("protocol/ALICE/FROM/BOB/ECDHE/CHECKER CORRECT/CHECK.SIG")
) { };

User_Alice::~User_Alice() { };

User_Bob::User_Bob() : IUser(
	string("protocol/BOB/RSA/PUBLIC_KEY/PUBLIC_KEY.pem"),
	string("protocol/BOB/RSA/PRIVATE_KEY/PRIVATE_KEY.pem"),
	string("protocol/BOB/FROM/CA_SERVER/RSA/SIGN_BOB_PUBLIC_KEY.sig"),
	string("protocol/BOB/FROM/CA_SERVER/RSA/PUBLIC_KEY/PUBLIC_KEY.pem"),
	string("protocol/BOB/FROM/ALICE/RSA/PUBLIC_KEY/PUBLIC_KEY.pem"),
	string("protocol/BOB/FROM/ALICE/RSA/SIGN_ALICE_PUBLIC_KEY.sig"),

	string("protocol/BOB/RSA/ECDHE/PUBLIC POINT/EncRSA_Qx.cor"),
	string("protocol/BOB/RSA/ECDHE/PUBLIC POINT/EncRSA_Qy.cor"),

	string("protocol/BOB/FROM/ALICE/RSA/ECDHE/PUBLIC POINT/EncRSA_Qx.cor"),
	string("protocol/BOB/FROM/ALICE/RSA/ECDHE/PUBLIC POINT/EncRSA_Qy.cor"),
	string("protocol/BOB/FROM/ALICE/ECDHE/PUBLIC POINT/Qx.cor"),
	string("protocol/BOB/FROM/ALICE/ECDHE/PUBLIC POINT/Qy.cor"),

	string("protocol/BOB/ECDHE/SESSION KEY/SECRET.KEY"),
	string("protocol/BOB/ECDHE/CHECKER CORRECT/CHECK.SIG"),
	string("protocol/BOB/FROM/ALICE/ECDHE/CHECKER CORRECT/CHECK.SIG")
) { };

User_Bob::~User_Bob() { };

void IUser::GenerateKeyPair(){
	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);

	UserRSA = RSA_new();
	RSA_generate_key_ex(UserRSA, 4096, e, nullptr);

	UserPublicKey = BIO_new_file(strRSA_Path_UserPublicKey.data(), "wb");
	PEM_write_bio_RSAPublicKey(UserPublicKey, UserRSA);
	BIO_free_all(UserPublicKey);

	UserPrivateKey = BIO_new_file(strRSA_Path_UserPrivateKey.data(), "wb");
	PEM_write_bio_RSAPrivateKey(UserPrivateKey, UserRSA, nullptr, nullptr, 0, nullptr, nullptr);
	BIO_free_all(UserPrivateKey);

	BN_free(e);
	RSA_free(UserRSA);
}

bool IUser::checkSignHashPublicKey(string& Path_SignHashUserPublicKey, string& Path_UserPublicKey) {
	auto HashFunction = new AlgorithmSHA512::SHA512;
	fstream FileInput;

	//Read User's PublicKey
	FileInput.open(Path_UserPublicKey, ios_base::in | ios_base::binary);
	
	//Get HashUserPublicKey
	auto UserPublicKey = new vector<uint8_t>();
	while (FileInput.peek() != -1) { UserPublicKey->push_back(FileInput.get()); }

	auto HashUserPublicKey = HashFunction->GetHash(UserPublicKey);

	FileInput.close();

	//Read User's SignHashUserPublicKey
	FileInput.open(Path_SignHashUserPublicKey, ios_base::in | ios_base::binary);

	//Get SignHashUserPublicKey
	auto SignHashUserPublicKey = new vector<uint8_t>();
	while (FileInput.peek() != -1) { SignHashUserPublicKey->push_back(FileInput.get()); }

	FileInput.close();

	RSA* checkPubKeyCARSA = RSA_new();	
	BIO* CAServerPublicKey = BIO_new_file(strRSA_Path_CAPublicKey.data(), "rb");
	checkPubKeyCARSA = PEM_read_bio_RSAPublicKey(CAServerPublicKey, &checkPubKeyCARSA, nullptr, nullptr);

	auto decryptHashUserPubKey = new vector<uint8_t>(HashUserPublicKey->size(), 0);

	RSA_public_decrypt(SignHashUserPublicKey->size(), SignHashUserPublicKey->data(), decryptHashUserPubKey->data(), checkPubKeyCARSA, RSA_PKCS1_PADDING);

	//Check, that RSA_Decrypt(CAPublicKey, SignHashUserPublicKey) == HashUserPublicKey
	if (string(decryptHashUserPubKey->begin(), decryptHashUserPubKey->end()) != string(HashUserPublicKey->begin(), HashUserPublicKey->end())) { 
		
		RSA_free(checkPubKeyCARSA);
		delete HashFunction;
		delete UserPublicKey;
		delete HashUserPublicKey;
		delete SignHashUserPublicKey;
		delete decryptHashUserPubKey;
		BIO_free_all(CAServerPublicKey);

		return false; 
	}

	RSA_free(checkPubKeyCARSA);
	delete HashFunction;
	delete UserPublicKey;
	delete HashUserPublicKey;
	delete SignHashUserPublicKey;
	delete decryptHashUserPubKey;
	BIO_free_all(CAServerPublicKey);

	return true;
};

vector<uint8_t>* IUser::GetFileHash(string& strPath_File) {
	auto HashFunction = new AlgorithmSHA512::SHA512;
	fstream FileInput;

	//CA sign User's PublicKey
	FileInput.open(strRSA_Path_UserPublicKey, ios_base::in | ios_base::binary);

	auto UserPublicKey = new vector<uint8_t>();
	while (FileInput.peek() != -1) { UserPublicKey->push_back(FileInput.get()); }

	auto HashPublicKey = HashFunction->GetHash(UserPublicKey);

	FileInput.close();
	delete HashFunction;
	delete UserPublicKey;
	return HashPublicKey;
};

void IUser::Send_SignHashUserPublicKey_UserPublicKey(IUser& User){
	fstream FileInput;
	fstream FileOutput;

	//Send PublicKey
	FileInput.open(strRSA_Path_UserPublicKey, ios_base::in | ios_base::binary);
	FileOutput.open(User.strRSA_Path_FriendPublicKey, ios_base::out | ios_base::binary);

	while (FileInput.peek() != -1) { FileOutput.put(FileInput.get()); }

	FileInput.close();
	FileOutput.close();

	//Send SignHashUserPublicKey
	FileInput.open(strRSA_Signature_UserPublicKey, ios_base::in | ios_base::binary);
	FileOutput.open(User.strRSA_Signature_FriendPublicKey, ios_base::out | ios_base::binary);

	while (FileInput.peek() != -1) { FileOutput.put(FileInput.get()); }

	FileInput.close();
	FileOutput.close();
};

void IUser::Calculate_ECDHE_Parametrs(){
	//Generate Pseudo Random Number
	CSPRNG generatorPRN;
	vector<uint8_t>* PRN = generatorPRN.GeneratePRN(1024);
	//Get Secret Key for Elliptic Curve
	d.FromString(hexStr(PRN), 16);
	//Get Public Elliptic Curve Point
	Q = ECDSA.MultiplyOnBasePoint(d);

	//RSA Encryption Public Elliptic Curve Point Q
	RSA* RSAEncryptPublicEllipticCurveCoordinates = RSA_new();
	BIO* FriendPublicKey = BIO_new_file(strRSA_Path_FriendPublicKey.data(), "rb");
	RSAEncryptPublicEllipticCurveCoordinates = PEM_read_bio_RSAPublicKey(FriendPublicKey, &RSAEncryptPublicEllipticCurveCoordinates, nullptr, nullptr);

	//Encryption X coordinate
	auto Encryption_X_Coordinate = new vector<uint8_t>(RSA_size(RSAEncryptPublicEllipticCurveCoordinates), 0);
	vector<uint8_t> X_Coordinate(Q.first.begin(), Q.first.end());
	RSA_public_encrypt(X_Coordinate.size(), X_Coordinate.data(), Encryption_X_Coordinate->data(), RSAEncryptPublicEllipticCurveCoordinates, RSA_PKCS1_PADDING);

	//Encryption Y coordinate
	auto Encryption_Y_Coordinate = new vector<uint8_t>(RSA_size(RSAEncryptPublicEllipticCurveCoordinates), 0);
	vector<uint8_t> Y_Coordinate(Q.second.begin(), Q.second.end());
	RSA_public_encrypt(Y_Coordinate.size(), Y_Coordinate.data(), Encryption_Y_Coordinate->data(), RSAEncryptPublicEllipticCurveCoordinates, RSA_PKCS1_PADDING);

	//Write Result to Files
	fstream FileOutput;

	FileOutput.open(strRSA_ECDHE_User_X_CoordinatePublicPointQ, ios_base::out | ios_base::binary);
	for (uint32_t i = 0; i < Encryption_X_Coordinate->size(); i++) FileOutput.put((*Encryption_X_Coordinate)[i]);
	FileOutput.close();

	FileOutput.open(strRSA_ECDHE_User_Y_CoordinatePublicPointQ, ios_base::out | ios_base::binary);
	for (uint32_t i = 0; i < Encryption_Y_Coordinate->size(); i++) FileOutput.put((*Encryption_Y_Coordinate)[i]);
	FileOutput.close();

	RSA_free(RSAEncryptPublicEllipticCurveCoordinates);
	BIO_free_all(FriendPublicKey);
	delete PRN;
	delete Encryption_X_Coordinate;
	delete Encryption_Y_Coordinate;
};

void IUser::Send_PublicUserEllipticCurvePointQ(IUser& User){
	fstream FileInput;
	fstream FileOutput;

	//Send RSA Encryption X Coordinate of Elliptic Curve Point Q to User
	FileInput.open(strRSA_ECDHE_User_X_CoordinatePublicPointQ, ios_base::in | ios_base::binary);
	FileOutput.open(User.strRSA_ECDHE_Friend_X_CoordinatePublicPointQ, ios_base::out | ios_base::binary);

	while (FileInput.peek() != -1) { FileOutput.put(FileInput.get()); }

	FileInput.close();
	FileOutput.close();

	//Send RSA Encryption Y Coordinate of Elliptic Curve Point Q to User
	FileInput.open(strRSA_ECDHE_User_Y_CoordinatePublicPointQ, ios_base::in | ios_base::binary);
	FileOutput.open(User.strRSA_ECDHE_Friend_Y_CoordinatePublicPointQ, ios_base::out | ios_base::binary);

	while (FileInput.peek() != -1) { FileOutput.put(FileInput.get()); }

	FileInput.close();
	FileOutput.close();
}

void IUser::CalculateSymmetricSessionKey(){
	//RSA Decryption Friend's Public Point Q
	RSA* RSADecryptFriendPublicEllipticCurveCoordinates = RSA_new();
	BIO* UserPrivateKey = BIO_new_file(strRSA_Path_UserPrivateKey.data(), "rb");
	RSADecryptFriendPublicEllipticCurveCoordinates = PEM_read_bio_RSAPrivateKey(UserPrivateKey, &RSADecryptFriendPublicEllipticCurveCoordinates, nullptr, nullptr);

	//Read Friend's X Coordinate
	fstream FileInput;
	FileInput.open(strRSA_ECDHE_Friend_X_CoordinatePublicPointQ, ios_base::in | ios_base::binary);

	//Get Friend's X Coordinate
	vector<uint8_t> EncryptionFriend_X_Coordinate;
	while (FileInput.peek() != -1) { EncryptionFriend_X_Coordinate.push_back(FileInput.get()); }
	FileInput.close();

	//Decrypt X Coordinate
	auto DecryptionFriend_X_Coordinate = new vector<uint8_t>(RSA_size(RSADecryptFriendPublicEllipticCurveCoordinates), 0);
	auto X_CoordinateSize = RSA_private_decrypt(EncryptionFriend_X_Coordinate.size(), EncryptionFriend_X_Coordinate.data(), DecryptionFriend_X_Coordinate->data(), RSADecryptFriendPublicEllipticCurveCoordinates, RSA_PKCS1_PADDING);
	EncryptionFriend_X_Coordinate.clear();

	//Read Friend's Y Coordinate
	FileInput.open(strRSA_ECDHE_Friend_Y_CoordinatePublicPointQ, ios_base::in | ios_base::binary);

	//Get Friend's Y Coordinate
	vector<uint8_t> EncryptionFriend_Y_Coordinate;
	while (FileInput.peek() != -1) { EncryptionFriend_Y_Coordinate.push_back(FileInput.get()); }
	FileInput.close();

	//Decrypt Y Coordinate
	auto DecryptionFriend_Y_Coordinate = new vector<uint8_t>(RSA_size(RSADecryptFriendPublicEllipticCurveCoordinates), 0);
	auto Y_CoordinateSize = RSA_private_decrypt(EncryptionFriend_Y_Coordinate.size(), EncryptionFriend_Y_Coordinate.data(), DecryptionFriend_Y_Coordinate->data(), RSADecryptFriendPublicEllipticCurveCoordinates, RSA_PKCS1_PADDING);
	EncryptionFriend_Y_Coordinate.clear();

	//Write Result to Files
	fstream FileOutput;

	//Write X_Coordinate
	FileOutput.open(strECDHE_Friend_X_CoordinatePublicPointQ, ios_base::out | ios_base::binary);
	for (uint32_t i = 0; i < X_CoordinateSize; i++) FileOutput.put((*DecryptionFriend_X_Coordinate)[i]);
	FileOutput.close();

	//Write Y_Coordinate
	FileOutput.open(strECDHE_Friend_Y_CoordinatePublicPointQ, ios_base::out | ios_base::binary);
	for (uint32_t i = 0; i < Y_CoordinateSize; i++) FileOutput.put((*DecryptionFriend_Y_Coordinate)[i]);
	FileOutput.close();

	RSA_free(RSADecryptFriendPublicEllipticCurveCoordinates);
	BIO_free_all(UserPrivateKey);

	//Calculate Common Session Key
	ECPoint FriendQ(&ECDSA);
	FriendQ.setCoordinate(
		string(DecryptionFriend_X_Coordinate->begin(), DecryptionFriend_X_Coordinate->begin() + X_CoordinateSize),
		string(DecryptionFriend_Y_Coordinate->begin(), DecryptionFriend_Y_Coordinate->begin() + Y_CoordinateSize)
	);
	ECPoint SecretPoint = FriendQ*d;
	auto X_CoordinateSecretPoint = SecretPoint.getXCoordinate();
	
	//Get Hash of X Coordinate of Secret Point
	auto HashFunction = new AlgorithmSHA512::SHA512;
	auto X_CoordinateSecretPointHash = HashFunction->GetHash(&vector<uint8_t>(X_CoordinateSecretPoint.begin(), X_CoordinateSecretPoint.end()));
	
	SessionKey = new vector<uint8_t>(X_CoordinateSecretPointHash->begin(), X_CoordinateSecretPointHash->begin() + 32);

	//Get Y Coordinate to Check Correct SessionKey
	CorrectSessionKeyCheck = SecretPoint.getYCoordinate();

	//Write Session Key
	FileOutput.open(strECDHE_UserSessionKey, ios_base::out | ios_base::binary);
	for (uint32_t i = 0; i < SessionKey->size(); i++) FileOutput.put((*SessionKey)[i]);
	FileOutput.close();

	delete SessionKey;
	delete X_CoordinateSecretPointHash;
	delete HashFunction;
	delete DecryptionFriend_X_Coordinate;
	delete DecryptionFriend_Y_Coordinate;
}

void IUser::Send_CheckCorrectSessionKey(IUser& User){
	//Get Hash of string 'CorrectSessionKeyCheck'
	auto HashFunction = new AlgorithmSHA512::SHA512;
	auto CheckCorrectSessionKeyHash = HashFunction->GetHash(&vector<uint8_t>(CorrectSessionKeyCheck.begin(), CorrectSessionKeyCheck.end()));

	//AES256 with Session Key Encryption 'CheckCorrectSessionKeyHash' 
	AES_256 AES;
	
	//Read Session Key
	SessionKey = new vector<uint8_t>;
	fstream FileInput;
	FileInput.open(strECDHE_UserSessionKey, ios_base::in | ios_base::binary);
	while (FileInput.peek() != -1) { SessionKey->push_back(FileInput.get()); }
	FileInput.close();

	//Encryption 'CheckCorrectSessionKeyHash' 
	auto EncryptionCheckCorrectSessionKeyHash = AES.Encrypt(CheckCorrectSessionKeyHash, SessionKey);

	//Write Result to File
	fstream FileOutput;

	//Write EncryptionCheckCorrectSessionKeyHash
	FileOutput.open(strECDHE_UserCheckCorrectSessionKey, ios_base::out | ios_base::binary);
	for (uint32_t i = 0; i < EncryptionCheckCorrectSessionKeyHash->size(); i++) FileOutput.put((*EncryptionCheckCorrectSessionKeyHash)[i]);
	FileOutput.close();

	delete HashFunction;
	delete SessionKey;
	delete CheckCorrectSessionKeyHash;
	delete EncryptionCheckCorrectSessionKeyHash;

	//Send EncryptionCheckCorrectSessionKeyHash to User
	FileInput.open(strECDHE_UserCheckCorrectSessionKey, ios_base::in | ios_base::binary);
	FileOutput.open(User.strECDHE_FriendCheckCorrectSessionKey, ios_base::out | ios_base::binary);

	while (FileInput.peek() != -1) { FileOutput.put(FileInput.get()); }

	FileInput.close();
	FileOutput.close();
}

bool IUser::checkCorrectSessionKey(){
	//Read Session Key
	SessionKey = new vector<uint8_t>;
	fstream FileInput;
	FileInput.open(strECDHE_UserSessionKey, ios_base::in | ios_base::binary);
	while (FileInput.peek() != -1) { SessionKey->push_back(FileInput.get()); }
	FileInput.close();

	//Read Friend EncryptionCheckCorrectSessionKeyHash
	auto EncryptionFriendCheckCorrectSessionKeyHash = new vector<uint8_t>;
	FileInput.open(strECDHE_FriendCheckCorrectSessionKey, ios_base::in | ios_base::binary);
	while (FileInput.peek() != -1) { EncryptionFriendCheckCorrectSessionKeyHash->push_back(FileInput.get()); }
	FileInput.close();

	//Decryption Friend EncryptionCheckCorrectSessionKeyHash
	AES_256 AES;
	auto DecryptionFriendCheckCorrectSessionKeyHash = AES.Decrypt(EncryptionFriendCheckCorrectSessionKeyHash, SessionKey);

	delete SessionKey;
	delete EncryptionFriendCheckCorrectSessionKeyHash;

	//Get Hash of string 'CorrectSessionKeyCheck'
	auto HashFunction = new AlgorithmSHA512::SHA512;
	auto CheckCorrectSessionKeyHash = HashFunction->GetHash(&vector<uint8_t>(CorrectSessionKeyCheck.begin(), CorrectSessionKeyCheck.end()));

	//Check, that CheckCorrectSessionKeyHash == DecryptionFriendCheckCorrectSessionKeyHash
	//If equal => return true
	//Else => return false
	for (uint32_t i = 0; i < CheckCorrectSessionKeyHash->size(); i++) {
		if ((*CheckCorrectSessionKeyHash)[i] == (*DecryptionFriendCheckCorrectSessionKeyHash)[i]) { continue; }
		else { return false; }
	}

	return true;
}

string IUser::hexStr(vector<uint8_t>* data) {
	string s(data->size() * 2, ' ');
	for (register uint64_t i = 0; i < data->size(); ++i) {
		s[2 * i] = hexmap[((*data)[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[(*data)[i] & 0x0F];
	}
	return s;
};

IUser::IUser(
	string& _strRSA_Path_UserPublicKey,
	string& _strRSA_Path_UserPrivateKey,
	string& _strRSA_Signature_UserPublicKey,
	string& _strRSA_Path_CAPublicKey,
	string& _strRSA_Path_FriendPublicKey,
	string& _strRSA_Signature_FriendPublicKey,

	string& _strRSA_ECDHE_User_X_CoordinatePublicPointQ,
	string& _strRSA_ECDHE_User_Y_CoordinatePublicPointQ,

	string& _strRSA_ECDHE_Friend_X_CoordinatePublicPointQ,
	string& _strRSA_ECDHE_Friend_Y_CoordinatePublicPointQ,
	string& _strECDHE_Friend_X_CoordinatePublicPointQ,
	string& _strECDHE_Friend_Y_CoordinatePublicPointQ,

	string& _strECDHE_UserSessionKey,
	string& _strECDHE_UserCheckCorrectSessionKey,
	string& _strECDHE_FriendCheckCorrectSessionKey
) {
	strRSA_Path_UserPublicKey = _strRSA_Path_UserPublicKey;
	strRSA_Path_UserPrivateKey = _strRSA_Path_UserPrivateKey;
	strRSA_Signature_UserPublicKey = _strRSA_Signature_UserPublicKey;
	strRSA_Path_CAPublicKey = _strRSA_Path_CAPublicKey;
	strRSA_Path_FriendPublicKey = _strRSA_Path_FriendPublicKey;
	strRSA_Signature_FriendPublicKey = _strRSA_Signature_FriendPublicKey;

	strRSA_ECDHE_User_X_CoordinatePublicPointQ = _strRSA_ECDHE_User_X_CoordinatePublicPointQ;
	strRSA_ECDHE_User_Y_CoordinatePublicPointQ = _strRSA_ECDHE_User_Y_CoordinatePublicPointQ;

	strRSA_ECDHE_Friend_X_CoordinatePublicPointQ = _strRSA_ECDHE_Friend_X_CoordinatePublicPointQ;
	strRSA_ECDHE_Friend_Y_CoordinatePublicPointQ = _strRSA_ECDHE_Friend_Y_CoordinatePublicPointQ;
	strECDHE_Friend_X_CoordinatePublicPointQ = _strECDHE_Friend_X_CoordinatePublicPointQ;
	strECDHE_Friend_Y_CoordinatePublicPointQ = _strECDHE_Friend_Y_CoordinatePublicPointQ;

	strECDHE_UserSessionKey = _strECDHE_UserSessionKey;
	strECDHE_UserCheckCorrectSessionKey = _strECDHE_UserCheckCorrectSessionKey;
	strECDHE_FriendCheckCorrectSessionKey = _strECDHE_FriendCheckCorrectSessionKey;
};

IUser::~IUser() { };

void Certificate_Authority_Server::GenerateKeyPair(){
	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);

	CAServerRSA = RSA_new();
	RSA_generate_key_ex(CAServerRSA, 4096, e, nullptr);

	CAServerPublicKey = BIO_new_file("protocol/CA_SERVER/RSA/PUBLIC_KEY/PUBLIC_KEY.pem", "wb");
	PEM_write_bio_RSAPublicKey(CAServerPublicKey, CAServerRSA);
	BIO_free_all(CAServerPublicKey);

	CAServerPublicKey = BIO_new_file("protocol/ALICE/FROM/CA_SERVER/RSA/PUBLIC_KEY/PUBLIC_KEY.pem", "wb");
	PEM_write_bio_RSAPublicKey(CAServerPublicKey, CAServerRSA);
	BIO_free_all(CAServerPublicKey);

	CAServerPublicKey = BIO_new_file("protocol/BOB/FROM/CA_SERVER/RSA/PUBLIC_KEY/PUBLIC_KEY.pem", "wb");
	PEM_write_bio_RSAPublicKey(CAServerPublicKey, CAServerRSA);
	BIO_free_all(CAServerPublicKey);

	CAServerPrivateKey = BIO_new_file("protocol/CA_SERVER/RSA/PRIVATE_KEY/PRIVATE_KEY.pem", "wb");
	PEM_write_bio_RSAPrivateKey(CAServerPrivateKey, CAServerRSA, nullptr, nullptr, 0, nullptr, nullptr);
	BIO_free_all(CAServerPrivateKey);

	BN_free(e);
	RSA_free(CAServerRSA);
}

Certificate_Authority_Server::Certificate_Authority_Server(){ };

Certificate_Authority_Server::~Certificate_Authority_Server(){ };

void Certificate_Authority_Server::signatureHashPublicKey(vector<uint8_t>* HashPublicKey, const IUser& User){
	CAServerRSA = RSA_new();
	CAServerPrivateKey = BIO_new_file("protocol/CA_SERVER/RSA/PRIVATE_KEY/PRIVATE_KEY.pem", "rb");
	CAServerPublicKey = BIO_new_file("protocol/CA_SERVER/RSA/PUBLIC_KEY/PUBLIC_KEY.pem", "rb");
	CAServerRSA = PEM_read_bio_RSAPrivateKey(CAServerPrivateKey, &CAServerRSA, nullptr, nullptr);
	CAServerRSA = PEM_read_bio_RSAPublicKey(CAServerPublicKey, &CAServerRSA, nullptr, nullptr);
	
	auto signHashUserPubKey = new vector<uint8_t>(RSA_size(CAServerRSA), 0);

	RSA_private_encrypt(HashPublicKey->size(), HashPublicKey->data(), signHashUserPubKey->data(), CAServerRSA, RSA_PKCS1_PADDING);
	
	//CAServer send to User Message with SIGN_User_PUBLIC_KEY.sig
	fstream FileOutput;
	FileOutput.open(User.strRSA_Signature_UserPublicKey, ios_base::out | ios_base::binary);
	for (unsigned char i : *signHashUserPubKey) { FileOutput.put(i); }

	delete HashPublicKey;
	delete signHashUserPubKey;
	FileOutput.close();
	BIO_free_all(CAServerPrivateKey);
	BIO_free_all(CAServerPublicKey);
	RSA_free(CAServerRSA);
};