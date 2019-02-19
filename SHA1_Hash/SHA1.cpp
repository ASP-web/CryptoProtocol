#include "SHA1.h"

void SHA1::PaddingTheMessage(){
	union Transformation {
		uint8_t BytesOfNumber[8];
		uint64_t qwNumber;
	};
	Transformation transformationNumbers;

	uint8_t byLastBlockSize = (byarrMessage->size()) % 64;
	uint8_t byPaddingSize = 64 - byLastBlockSize;

	byarrMessage->push_back(0x80);

	uint8_t wSizeOfZeroPaddingBits = (448 - (8 * byLastBlockSize + 8)) / 8;
	for (uint8_t i = 0; i < wSizeOfZeroPaddingBits; i++) { byarrMessage->push_back(0x00); }

	transformationNumbers.qwNumber = 8 * byLastBlockSize;
	for (int i = 7; i > -1; i--) { byarrMessage->push_back(transformationNumbers.BytesOfNumber[i]); }
}

SHA1::SHA1(){

}

SHA1::~SHA1(){

}
