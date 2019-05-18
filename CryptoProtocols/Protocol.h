#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <vector>
#include <string>

#include "../AES256_BlocksCipher/AES.h"
#include "../SHA512_Hash/SHA512.h"
#include "../CSPRNG/CSPRNG.h"
#include "../ECDSA/ECDSA.h"

using namespace std;

class IUser {
public:
	ECDSA_GOST_256 ECDSA;
	RSA* UserRSA = nullptr;
	BIO* UserPublicKey = nullptr;
	BIO* UserPrivateKey = nullptr;

	//ECDHE User's Parameters
	bigint d;
	pair<string, string> Q;

	//Common Data
	vector<uint8_t>* SessionKey;
	string CorrectSessionKeyCheck;

	//Paths
	string strRSA_Path_UserPublicKey;
	string strRSA_Path_UserPrivateKey;
	string strRSA_Signature_UserPublicKey;
	string strRSA_Path_CAPublicKey;
	string strRSA_Path_FriendPublicKey;
	string strRSA_Signature_FriendPublicKey;

	string strRSA_ECDHE_User_X_CoordinatePublicPointQ;
	string strRSA_ECDHE_User_Y_CoordinatePublicPointQ;

	string strRSA_ECDHE_Friend_X_CoordinatePublicPointQ;
	string strRSA_ECDHE_Friend_Y_CoordinatePublicPointQ;
	string strECDHE_Friend_X_CoordinatePublicPointQ;
	string strECDHE_Friend_Y_CoordinatePublicPointQ;

	string strECDHE_UserSessionKey;
	string strECDHE_UserCheckCorrectSessionKey;
	string strECDHE_FriendCheckCorrectSessionKey;

	string strUser_MessagePath;
	string strUser_EncryptionMessagePath;
	string strUser_Parametr_R_DigitalSignMessagePath;
	string strUser_Parametr_S_DigitalSignMessagePath;
	string strUser_X_KeyCheckDigitalSignMessagePath;
	string strUser_Y_KeyCheckDigitalSignMessagePath;
	string strUser_AnswerPath;

	string strFriend_EncryptionMessagePath;
	string strFriend_DecryptionMessagePath;
	string strFriend_Parametr_R_DigitalSignMessagePath;
	string strFriend_Parametr_S_DigitalSignMessagePath;
	string strFriend_X_KeyCheckDigitalSignMessagePath;
	string strFriend_Y_KeyCheckDigitalSignMessagePath;
	string strFriend_AnswerPath;


	void GenerateKeyPair();

	bool checkSignHashPublicKey(string& Path_SignHashUserPublicKey, string& Path_UserPublicKey);

	vector<uint8_t>* GetFileHash(string& strPath_File);

	void Send_SignHashUserPublicKey_UserPublicKey(IUser& toUser);

	void Calculate_ECDHE_Parametrs();

	void Send_PublicUserEllipticCurvePointQ(IUser& toUser);

	void CalculateSymmetricSessionKey();

	void Send_CheckCorrectSessionKey(IUser& toUser);

	bool checkCorrectSessionKey();

	void CreateMessage();

	void SendMessage(IUser& toUser);

	void CheckMessage_CreateAnswer();

	void SendAnswer(IUser& toUser);

	bool CheckAnswer();

	string hexStr(vector<uint8_t> *data);

	IUser(
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
		string& _strECDHE_FriendCheckCorrectSessionKey,

		string& _strUser_MessagePath,
		string& _strUser_EncryptionMessagePath,
		string& _strUser_Parametr_R_DigitalSignMessagePath,
		string& _strUser_Parametr_S_DigitalSignMessagePath,
		string& _strUser_X_KeyCheckDigitalSignMessagePath,
		string& _strUser_Y_KeyCheckDigitalSignMessagePath,
		string& _strUser_AnswerPath,

		string& _strFriend_EncryptionMessagePath,
		string& _strFriend_DecryptionMessagePath,
		string& _strFriend_Parametr_R_DigitalSignMessagePath,
		string& _strFriend_Parametr_S_DigitalSignMessagePath,
		string& _strFriend_X_KeyCheckDigitalSignMessagePath,
		string& _strFriend_Y_KeyCheckDigitalSignMessagePath,
		string& _strFriend_AnswerPath
	);
	~IUser();
};

class User_Alice : public IUser {
public:
	User_Alice();
	~User_Alice();
};

class User_Bob : public IUser {
public:
	User_Bob();
	~User_Bob();
};

class Certificate_Authority_Server {
	RSA* CAServerRSA = nullptr;
	BIO* CAServerPublicKey = nullptr;
	BIO* CAServerPrivateKey = nullptr;

public:
	void GenerateKeyPair();

	Certificate_Authority_Server();
	~Certificate_Authority_Server();

	void signatureHashPublicKey(vector<uint8_t>* HashPublicKey, const IUser& User);
};

#endif//PROTOCOL_H
