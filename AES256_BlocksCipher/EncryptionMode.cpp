#include "EncryptionMode.h"
#include <random>
#include <chrono>


/*Start InterfaceEncryptionMode Methods Realization*/
void IEncryptionMode::AdditionBlocksRatio(vector<uint8_t>* arrbyBufferPublicText) {
	//Work by GOST 34.12-2015
	arrbyBufferPublicText->push_back(0x80);
	for (uint8_t i = 0; i < (arrbyBufferPublicText->size() % 16); i++) { arrbyBufferPublicText->push_back(0x00); }
}
/*End InterfaceEncryptionMode Methods Realization*/


/*Start ECB Methods Realization*/
void ECB::ThreadEncription(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock) {
	vector<uint8_t> byarrBlockCipherText;
	for (uint64_t qwCurrentBlock = qwStartBlock; qwCurrentBlock < qwEndBlock; qwCurrentBlock++) {
		byarrBlockCipherText = _pRijndael->Encrypt(vector<uint8_t>(byarrBufferPlainText->begin() + qwCurrentBlock * 16, byarrBufferPlainText->begin() + (qwCurrentBlock + 1) * 16), byarrKey);
		byarrBufferCipherText->insert(byarrBufferCipherText->end(), byarrBlockCipherText.begin(), byarrBlockCipherText.end());
		byarrBlockCipherText.clear();
	}
	return;
}

vector<uint8_t>* ECB::Encryption(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey) {
	//Check AdditionBlockRatio
	if (byarrBufferPlainText->size() % 16 != 0) { AdditionBlocksRatio(byarrBufferPlainText); }

	vector<uint8_t>* byarrBufferCipherText = new vector<uint8_t>;
	
	vector<thread*> ParentArrayChildThreads;
	vector<vector<uint8_t>> ThreadsBuffers_byarrCipherText(thread::hardware_concurrency());

	uint64_t qwSizePlainTextBlocks = byarrBufferPlainText->size() / 16;

	//Use One Main Thread Where SizePlainTextBlocks < 1024 for One CPU Thread
	if (qwSizePlainTextBlocks < thread::hardware_concurrency() * 1024) {
		ThreadEncription(byarrBufferCipherText, byarrBufferPlainText, byarrKey, 0, qwSizePlainTextBlocks);
		return byarrBufferCipherText;
	}

	/*Multi threading realization*/
	uint64_t qwSizeBufferOfBlocksToOneThread = byarrBufferPlainText->size() / (16 * thread::hardware_concurrency());
	
	uint64_t qwCurrentStartBlock = 0;
	uint64_t qwCurrentEndBlock = qwCurrentStartBlock + qwSizeBufferOfBlocksToOneThread;
	uint8_t byCurrentThread = 0;
	while (qwCurrentStartBlock != qwSizePlainTextBlocks) {
		if ((ParentArrayChildThreads.size() == thread::hardware_concurrency() - 1)) {
			qwCurrentEndBlock = qwSizePlainTextBlocks;
			ParentArrayChildThreads.push_back(new thread([this, &byCurrentThread, &ThreadsBuffers_byarrCipherText, &byarrBufferPlainText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadEncription(&ThreadsBuffers_byarrCipherText[byCurrentThread], byarrBufferPlainText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
			qwCurrentStartBlock = qwCurrentEndBlock;
		}
		else {
			ParentArrayChildThreads.push_back(new thread([this, &byCurrentThread, &ThreadsBuffers_byarrCipherText, &byarrBufferPlainText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadEncription(&ThreadsBuffers_byarrCipherText[byCurrentThread], byarrBufferPlainText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
			qwCurrentStartBlock = qwCurrentEndBlock;
			qwCurrentEndBlock += qwSizeBufferOfBlocksToOneThread;
		}
	}

	for (uint8_t i = 0; i < ParentArrayChildThreads.size(); i++) {
		//Parent Wait your Child Threads For Write Final Result
		ParentArrayChildThreads[i]->join();
		byarrBufferCipherText->insert(byarrBufferCipherText->end(), ThreadsBuffers_byarrCipherText[i].begin(), ThreadsBuffers_byarrCipherText[i].end());
		delete ParentArrayChildThreads[i];
		ThreadsBuffers_byarrCipherText[i].clear();
	}

	return byarrBufferCipherText;
}

void ECB::ThreadDecryption(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock) {
	vector<uint8_t> byarrBlockPlainText;
	for (uint64_t dwCurrentBlock = qwStartBlock; dwCurrentBlock < qwEndBlock; dwCurrentBlock++) {
		byarrBlockPlainText = _pRijndael->Decrypt(vector<uint8_t>(byarrBufferCipherText->begin() + dwCurrentBlock * 16, byarrBufferCipherText->begin() + (dwCurrentBlock + 1) * 16), byarrKey);
		byarrBufferPlainText->insert(byarrBufferPlainText->end(), byarrBlockPlainText.begin(), byarrBlockPlainText.end());
		byarrBlockPlainText.clear();
	}
	return;
}

vector<uint8_t>* ECB::Decryption(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey) {
	
	vector<uint8_t>* byarrBufferPlainText = new vector<uint8_t>;

	vector<thread*> ParentArrayChildThreads;
	vector<vector<uint8_t>> ThreadsBuffers_byarrPlainText(thread::hardware_concurrency());

	uint64_t qwSizeCipherTextBlocks = byarrBufferCipherText->size() / 16;

	//Use One Main Thread Where SizeCipherTextBlocks < 1024 for One CPU Thread
	if (qwSizeCipherTextBlocks < thread::hardware_concurrency() * 1024) {
		ThreadDecryption(byarrBufferPlainText, byarrBufferCipherText, byarrKey, 0, qwSizeCipherTextBlocks);
		return byarrBufferPlainText;
	}

	/*Multi threading realization*/
	uint64_t qwSizeBufferOfBlocksToOneThread = byarrBufferCipherText->size() / (16 * thread::hardware_concurrency());

	uint64_t qwCurrentStartBlock = 0;
	uint64_t qwCurrentEndBlock = qwCurrentStartBlock + qwSizeBufferOfBlocksToOneThread;
	uint8_t byCurrentThread = 0;
	while (qwCurrentStartBlock != qwSizeCipherTextBlocks) {
		if ((ParentArrayChildThreads.size() == thread::hardware_concurrency() - 1)) {
			qwCurrentEndBlock = qwSizeCipherTextBlocks;
			ParentArrayChildThreads.push_back(new thread([this, &byCurrentThread, &ThreadsBuffers_byarrPlainText, &byarrBufferCipherText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadDecryption(&ThreadsBuffers_byarrPlainText[byCurrentThread], byarrBufferCipherText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
			qwCurrentStartBlock = qwCurrentEndBlock;
		}
		else {
			ParentArrayChildThreads.push_back(new thread([this, &byCurrentThread, &ThreadsBuffers_byarrPlainText, &byarrBufferCipherText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadDecryption(&ThreadsBuffers_byarrPlainText[byCurrentThread], byarrBufferCipherText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
			qwCurrentStartBlock = qwCurrentEndBlock;
			qwCurrentEndBlock += qwSizeBufferOfBlocksToOneThread;
		}
	}

	for (uint8_t i = 0; i < ParentArrayChildThreads.size(); i++) {
		//Parent Wait your Child Threads For Write Final Result
		ParentArrayChildThreads[i]->join();
		byarrBufferPlainText->insert(byarrBufferPlainText->end(), ThreadsBuffers_byarrPlainText[i].begin(), ThreadsBuffers_byarrPlainText[i].end());
		delete ParentArrayChildThreads[i];
		ThreadsBuffers_byarrPlainText[i].clear();
	}

	return byarrBufferPlainText;
}
/*End ECB Methods Realization*/


/*Start CTR Methods Realization*/
void CTR::ThreadEncription(vector<uint8_t> IV, vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock){
	union FormattedGeneratorNumbers {
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;	

	for (uint8_t i = 0; i < 16; i++) { FormatIV.byArray[i] = IV[i]; }
	vector<uint8_t> _IV(IV);
	
	vector<uint8_t> byarrBlockCipherText;
	for (uint64_t qwCurrentBlock = qwStartBlock; qwCurrentBlock < qwEndBlock; qwCurrentBlock++) {
		byarrBlockCipherText = _pRijndael->Encrypt(vector<uint8_t>(_IV.begin(), _IV.end()), byarrKey);
		for (uint8_t i = 0; i < 16; i++) { byarrBlockCipherText[i] ^= (*byarrBufferPlainText)[qwCurrentBlock * 16 + i]; }

		//Add Counter += 1 (if dwCurrentBlock % 2 == 0 -> add +1 to hight 64 bits IV) (else -> add +1 to low 64 bits IV)
		if (qwCurrentBlock % 2 == 0) { FormatIV.qwArray[0]++; }
		else { FormatIV.qwArray[1]++; }

		//Update Counter
		_IV.clear();
		for (uint8_t i : FormatIV.byArray) { _IV.push_back(i); }

		//Add Cipher Text in Buffer
		byarrBufferCipherText->insert(byarrBufferCipherText->end(), byarrBlockCipherText.begin(), byarrBlockCipherText.end());
		byarrBlockCipherText.clear();
	}
	return;
}

vector<uint8_t>* CTR::Encryption(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey){
	union FormattedGeneratorNumbers{
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	//Get current time in nanoseconds to mt19937_64 Seed
	auto current_time_now = chrono::high_resolution_clock::now();	
	mt19937_64 urandom_generator;
	//Set Seed
	urandom_generator.seed(current_time_now.time_since_epoch().count());

	//Generate IV 
	FormatIV.qwArray[0] = urandom_generator();
	FormatIV.qwArray[1] = urandom_generator();

	//Write IV, Where IV = Counter 
	vector<uint8_t> IV;
	for (uint8_t i : FormatIV.byArray) { IV.push_back(i); }

	//Output Buffer
	vector<uint8_t>* byarrBufferCipherText = new vector<uint8_t>;

	//Insert IV in BufferCipherText
	byarrBufferCipherText->insert(byarrBufferCipherText->end(), IV.begin(), IV.end());

	//Check AdditionBlockRatio
	if (byarrBufferPlainText->size() % 16 != 0) { AdditionBlocksRatio(byarrBufferPlainText); }

	vector<thread*> ParentArrayChildThreads;
	vector<vector<uint8_t>> ThreadsBuffers_byarrCipherText(thread::hardware_concurrency());

	uint64_t qwSizePlainTextBlocks = byarrBufferPlainText->size() / 16;

	//Use One Main Thread Where SizePlainTextBlocks < 1024 for One CPU Thread
	if (qwSizePlainTextBlocks < thread::hardware_concurrency() * 1024) {
		ThreadEncription(IV, byarrBufferCipherText, byarrBufferPlainText, byarrKey, 0, qwSizePlainTextBlocks);
		return byarrBufferCipherText;
	}

	/*Multi threading realization*/
	uint64_t qwSizeBufferOfBlocksToOneThread = byarrBufferPlainText->size() / (16 * thread::hardware_concurrency());
	
	uint64_t qwCurrentStartBlock = 0;
	uint64_t qwCurrentEndBlock = qwCurrentStartBlock + qwSizeBufferOfBlocksToOneThread;
	uint8_t byCurrentThread = 0;
	while (qwCurrentStartBlock != qwSizePlainTextBlocks) {
		if ((ParentArrayChildThreads.size() == thread::hardware_concurrency() - 1)) {
			qwCurrentEndBlock = qwSizePlainTextBlocks;
			ParentArrayChildThreads.push_back(new thread([this, &IV, &byCurrentThread, &ThreadsBuffers_byarrCipherText, &byarrBufferPlainText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadEncription(IV, &ThreadsBuffers_byarrCipherText[byCurrentThread], byarrBufferPlainText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
			qwCurrentStartBlock = qwCurrentEndBlock;
		}
		else {
			ParentArrayChildThreads.push_back(new thread([this, &IV, &byCurrentThread, &ThreadsBuffers_byarrCipherText, &byarrBufferPlainText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadEncription(IV, &ThreadsBuffers_byarrCipherText[byCurrentThread], byarrBufferPlainText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
		}

		//Update Counter For Next Thread
		for (auto qwCurrentBlock = qwCurrentStartBlock; qwCurrentBlock < qwCurrentEndBlock; qwCurrentBlock++) {
			//Add Counter += 1 (if dwCurrentBlock % 2 == 0 -> add +1 to hight 64 bits IV) (else -> add +1 to low 64 bits IV)
			if (qwCurrentBlock % 2 == 0) { FormatIV.qwArray[0]++; }
			else { FormatIV.qwArray[1]++; }
		}

		//Update qwCurrentStartBlock And qwCurrentEndBlock
		qwCurrentStartBlock = qwCurrentEndBlock;
		qwCurrentEndBlock += qwSizeBufferOfBlocksToOneThread;

		//Update Counter
		IV.clear();
		for (uint8_t i : FormatIV.byArray) { IV.push_back(i); }
	}

	for (uint8_t i = 0; i < ParentArrayChildThreads.size(); i++) {
		//Parent Wait your Child Threads For Write Final Result
		ParentArrayChildThreads[i]->join();
		byarrBufferCipherText->insert(byarrBufferCipherText->end(), ThreadsBuffers_byarrCipherText[i].begin(), ThreadsBuffers_byarrCipherText[i].end());
		delete ParentArrayChildThreads[i];
		ThreadsBuffers_byarrCipherText[i].clear();
	}

	return byarrBufferCipherText;
}

void CTR::ThreadDecryption(vector<uint8_t> IV, vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey, uint64_t qwStartBlock, uint64_t qwEndBlock) {
	union FormattedGeneratorNumbers {
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	for (uint8_t i = 0; i < 16; i++) { FormatIV.byArray[i] = IV[i]; }
	vector<uint8_t> _IV(IV);

	vector<uint8_t> byarrBlockCipherText;
	for (uint64_t qwCurrentBlock = qwStartBlock; qwCurrentBlock < qwEndBlock; qwCurrentBlock++) {
		byarrBlockCipherText = _pRijndael->Encrypt(vector<uint8_t>(_IV.begin(), _IV.end()), byarrKey);
		for (uint8_t i = 0; i < 16; i++) { byarrBlockCipherText[i] ^= (*byarrBufferCipherText)[qwCurrentBlock * 16 + i]; }

		//Revert add Counter +=1 because qwCurrentStartBlock Start with 1;
		//Add Counter += 1 (if dwCurrentBlock % 2 == 1 -> add +1 to hight 64 bits IV) (else -> add +1 to low 64 bits IV)
		if (qwCurrentBlock % 2 == 1) { FormatIV.qwArray[0]++; }
		else { FormatIV.qwArray[1]++; }

		//Update Counter
		_IV.clear();
		for (uint8_t i : FormatIV.byArray) { _IV.push_back(i); }

		//Add Cipher Text in Buffer
		byarrBufferPlainText->insert(byarrBufferPlainText->end(), byarrBlockCipherText.begin(), byarrBlockCipherText.end());
		byarrBlockCipherText.clear();
	}
	return;
}

vector<uint8_t>* CTR::Decryption(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey){
	union FormattedGeneratorNumbers {
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	//Write IV, Where IV = Counter 
	vector<uint8_t> IV(byarrBufferCipherText->begin(), byarrBufferCipherText->begin() + 16);
	for (uint8_t i = 0; i < 16; i++) { FormatIV.byArray[i] = IV[i]; }

	//Output Buffer
	vector<uint8_t>* byarrBufferPlainText = new vector<uint8_t>;

	vector<thread*> ParentArrayChildThreads;
	vector<vector<uint8_t>> ThreadsBuffers_byarrPlainText(thread::hardware_concurrency());

	uint64_t qwSizeCipherTextBlocks = byarrBufferCipherText->size() / 16;

	//Use One Main Thread Where SizePlainTextBlocks < 1024 for One CPU Thread
	if (qwSizeCipherTextBlocks < thread::hardware_concurrency() * 1024) {
		ThreadDecryption(IV, byarrBufferPlainText, byarrBufferCipherText, byarrKey, 1, qwSizeCipherTextBlocks);
		return byarrBufferPlainText;
	}

	/*Multi threading realization*/
	uint64_t qwSizeBufferOfBlocksToOneThread = byarrBufferCipherText->size() / (16 * thread::hardware_concurrency());

	uint64_t qwCurrentStartBlock = 1;
	uint64_t qwCurrentEndBlock = qwCurrentStartBlock + qwSizeBufferOfBlocksToOneThread;
	uint8_t byCurrentThread = 0;
	while (qwCurrentStartBlock != qwSizeCipherTextBlocks) {
		if ((ParentArrayChildThreads.size() == thread::hardware_concurrency() - 1)) {
			qwCurrentEndBlock = qwSizeCipherTextBlocks;
			ParentArrayChildThreads.push_back(new thread([this, &IV, &byCurrentThread, &ThreadsBuffers_byarrPlainText, &byarrBufferCipherText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadDecryption(IV, &ThreadsBuffers_byarrPlainText[byCurrentThread], byarrBufferCipherText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
			qwCurrentStartBlock = qwCurrentEndBlock;
		}
		else {
			ParentArrayChildThreads.push_back(new thread([this, &IV, &byCurrentThread, &ThreadsBuffers_byarrPlainText, &byarrBufferCipherText, &byarrKey, qwCurrentStartBlock, qwCurrentEndBlock]() { this->ThreadDecryption(IV, &ThreadsBuffers_byarrPlainText[byCurrentThread], byarrBufferCipherText, byarrKey, qwCurrentStartBlock, qwCurrentEndBlock); }));
			byCurrentThread++;
		}

		//Update Counter For Next Thread
		for (auto qwCurrentBlock = qwCurrentStartBlock; qwCurrentBlock < qwCurrentEndBlock; qwCurrentBlock++) {
			//Revert add Counter +=1 because dwCurrentBlock Start with 1;
			//Add Counter += 1 (if dwCurrentBlock % 2 == 1 -> add +1 to hight 64 bits IV) (else -> add +1 to low 64 bits IV)
			if (qwCurrentBlock % 2 == 1) { FormatIV.qwArray[0]++; }
			else { FormatIV.qwArray[1]++; }
		}

		//Update qwCurrentStartBlock And qwCurrentEndBlock
		qwCurrentStartBlock = qwCurrentEndBlock;
		qwCurrentEndBlock += qwSizeBufferOfBlocksToOneThread;

		//Update Counter
		IV.clear();
		for (uint8_t i : FormatIV.byArray) { IV.push_back(i); }
	}

	for (uint8_t i = 0; i < ParentArrayChildThreads.size(); i++) {
		//Parent Wait your Child Threads For Write Final Result
		ParentArrayChildThreads[i]->join();
		byarrBufferPlainText->insert(byarrBufferPlainText->end(), ThreadsBuffers_byarrPlainText[i].begin(), ThreadsBuffers_byarrPlainText[i].end());
		delete ParentArrayChildThreads[i];
		ThreadsBuffers_byarrPlainText[i].clear();
	}

	return byarrBufferPlainText;
}
/*End CTR Methods Realization*/


/*Start OFB Methods Realization*/
vector<uint8_t>* OFB::Encryption(vector<uint8_t>* byarrBufferPlainText, vector<uint8_t>* byarrKey) {
	union FormattedGeneratorNumbers {
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	//Get current time in nanoseconds to mt19937_64 Seed
	auto current_time_now = chrono::high_resolution_clock::now();
	mt19937_64 urandom_generator;
	//Set Seed
	urandom_generator.seed(current_time_now.time_since_epoch().count());

	//Generate IV 
	FormatIV.qwArray[0] = urandom_generator();
	FormatIV.qwArray[1] = urandom_generator();

	//Write IV, Where IV = Counter 
	vector<uint8_t> IV;
	for (uint8_t i : FormatIV.byArray) { IV.push_back(i); }

	//Output Buffer
	vector<uint8_t>* arrbyBufferCipherText = new vector<uint8_t>;

	//Insert IV in BufferCipherText
	arrbyBufferCipherText->insert(arrbyBufferCipherText->end(), IV.begin(), IV.end());

	//Check AdditionBlockRatio
	if (byarrBufferPlainText->size() % 16 != 0) { AdditionBlocksRatio(byarrBufferPlainText); }

	vector<uint8_t> BlockCipherText;
	for (uint32_t dwCurrentBlock = 0; dwCurrentBlock < (byarrBufferPlainText->size() / 16); dwCurrentBlock++) {

		IV = _pRijndael->Encrypt(vector<uint8_t>(IV.begin(), IV.end()), byarrKey);	

		for (uint8_t i = 0; i < 16; i++) { BlockCipherText.push_back(IV[i] ^ (*byarrBufferPlainText)[dwCurrentBlock * 16 + i]); }

		//Add Cipher Text in Buffer
		arrbyBufferCipherText->insert(arrbyBufferCipherText->end(), BlockCipherText.begin(), BlockCipherText.end());

		BlockCipherText.clear();
	}
	return arrbyBufferCipherText;
}

vector<uint8_t>* OFB::Decryption(vector<uint8_t>* byarrBufferCipherText, vector<uint8_t>* byarrKey) {
	union FormattedGeneratorNumbers {
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	//Write IV, Where IV = Counter 
	vector<uint8_t> IV(byarrBufferCipherText->begin(), byarrBufferCipherText->begin() + 16);
	for (uint8_t i = 0; i < 16; i++) { FormatIV.byArray[i] = IV[i]; }

	//Output Buffer
	vector<uint8_t>* arrbyBufferPlainText = new vector<uint8_t>;

	vector<uint8_t> BlockPlainText;
	for (uint32_t dwCurrentBlock = 1; dwCurrentBlock < (byarrBufferCipherText->size() / 16); dwCurrentBlock++) {

		IV = _pRijndael->Encrypt(vector<uint8_t>(IV.begin(), IV.end()), byarrKey);
		for (uint8_t i = 0; i < 16; i++) { BlockPlainText.push_back(IV[i] ^ (*byarrBufferCipherText)[dwCurrentBlock * 16 + i]); }

		//Add Cipher Text in Buffer
		arrbyBufferPlainText->insert(arrbyBufferPlainText->end(), BlockPlainText.begin(), BlockPlainText.end());

		BlockPlainText.clear();
	}
	return arrbyBufferPlainText;
}
/*End OFB Methods Realization*/