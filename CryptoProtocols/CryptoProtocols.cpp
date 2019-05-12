// CryptoProtocols.cpp : Defines the entry point for the console application.
//
#include "Protocol.h"
#include <chrono>

void ProtocolFirstStep(Certificate_Authority_Server& CA, IUser& User) {
	//User send to CAServer his HashUserPublicKey for Sign
	//CAServer send SignHashUserPublicKey to User
	CA.signatureHashPublicKey(User.GetFileHash(User.strRSA_Path_UserPublicKey), User);

	//Check, that RSA_Decrypt(CAPublicKey, SignHashUserPublicKey) == HashUserPublicKey
	//If true, then User have true SignHashUserPublicKey for install signal
	//Else false, then Man in the Middle listen signal channel, repeat Step 1 ProtocolFirstStep()
	if (!User.checkSignHashPublicKey(User.strRSA_Signature_UserPublicKey, User.strRSA_Path_UserPublicKey)) { cout << false << endl; ProtocolFirstStep(CA, User); }
}

void ProtocolSecondStep(IUser& Sender, IUser& Receiver) {
	//Sender Send to Receiver SignHashSenderPublicKey and SenderPublicKey
	Sender.Send_SignHashUserPublicKey_UserPublicKey(Receiver);

	//Receiver Check, that RSA_Decrypt(CAPublicKey, SignHashSenderPublicKey) == HashSenderPublicKey
	//If true, then Receiver have true SenderPublicKey for install signal
	//Else false, then Man in the Middle listen signal channel, repeat Step 2 ProtocolSecondStep()
	if (!Receiver.checkSignHashPublicKey(Receiver.strRSA_Signature_FriendPublicKey, Receiver.strRSA_Path_FriendPublicKey)) { cout << false << endl; ProtocolSecondStep(Sender, Receiver); }
}

void ProtocolThirdStep(IUser& User1, IUser& User2) {
	//User1 Calculate ECDHA Parameters
	// 1. Generate PseudoRandom Number and get from it the Private Key 'd' for CurvePoint (size of PseudoRandom Number is 1024 bytes) and ( 0 < d < q)
	// 2. Getting Public EllipticCurve Point Q = d*G, where G - base Point of EllipticCurve
	// 3. Encryption RSA EllipticCurve Point 'Q' Coordinates 'x' and 'y' [RSAenc(ReceiverPubKey, Q) = EncQ]
	User1.Calculate_ECDHE_Parametrs();

	//User2 Calculate ECDHA Parameters
	// 1. Generate PseudoRandom Number and get from it the Private Key 'd' for CurvePoint (size of PseudoRandom Number is 1024 bytes) and ( 0 < d < q)
	// 2. Getting Public EllipticCurve Point Q = d*G, where G - base Point of EllipticCurve
	// 3. Encryption RSA EllipticCurve Point 'Q' Coordinates 'x' and 'y' [RSAenc(ReceiverPubKey, Q) = EncQ]
	User2.Calculate_ECDHE_Parametrs();
	
	//User1 Send to User2 yours 'EncQ'
	User1.Send_PublicUserEllipticCurvePointQ(User2);

	//User2 Send to User1 yours 'EncQ'
	User2.Send_PublicUserEllipticCurvePointQ(User1);

	//User1 Calculate Common Symmetric Session Key and Information of Correct SessionKeyCheck 
	User1.CalculateSymmetricSessionKey();

	//User2 Calculate Common Symmetric Session Key and Information of Correct SessionKeyCheck 
	User2.CalculateSymmetricSessionKey();

	//User1 Send to User2 Encryption Hash of Information of Correct SessionKeyCheck
	User1.Send_CheckCorrectSessionKey(User2);

	//User2 Send to User1 Encryption Hash of Information of Correct SessionKeyCheck
	User2.Send_CheckCorrectSessionKey(User1);

	//Check, that User1CheckCorrectSessionKeyHash == DecryptionUser2CheckCorrectSessionKeyHash
	//If equal => User1 Session Key = User2 Session Key
	//Else => Man in the Middle, repeat Protocol Third Step
	if (!User1.checkCorrectSessionKey()) { cout << false << endl; ProtocolThirdStep(User1, User2); }

	//Check, that User2CheckCorrectSessionKeyHash == DecryptionUser1CheckCorrectSessionKeyHash
	//If equal => User2 Session Key = User1 Session Key
	//Else => Man in the Middle, repeat Protocol Third Step
	if (!User2.checkCorrectSessionKey()) { cout << false << endl; ProtocolThirdStep(User2, User1); }
}

int main()
{
	using myclock = chrono::steady_clock;

	Certificate_Authority_Server CA;
	myclock::time_point start = myclock::now();
	CA.GenerateKeyPair();
	myclock::time_point end = myclock::now();
	cout << "Time Certificate_Authority_Server Generate Key Pair: " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds" << endl;

	User_Bob Bob;
	start = myclock::now();
	Bob.GenerateKeyPair();
	end = myclock::now();
	cout << "Time User Bob Generate Key Pair: " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds" << endl;

	User_Alice Alice;
	start = myclock::now();
	Alice.GenerateKeyPair();
	end = myclock::now();
	cout << "Time User Alice Generate Key Pair: " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds" << endl;

	ProtocolFirstStep(CA, Alice);
	start = myclock::now();
	ProtocolFirstStep(CA, Bob);
	end = myclock::now();
	cout <<"Time First Step Protocol: " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds" << endl;
	
	start = myclock::now();
	ProtocolSecondStep(Alice, Bob);
	end = myclock::now();
	cout << "Time Second Step Protocol: " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds" << endl;
	ProtocolSecondStep(Bob, Alice);

	start = myclock::now();
	ProtocolThirdStep(Alice, Bob);
	end = myclock::now();
	cout << "Time Third Step Protocol: " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds" << endl;

    return 0;
}

