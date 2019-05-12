#include "SHA1.h"

#define Ch(x, y, z) (((x) & (y)) ^ ((~x) & (z)))
#define Parity(x, y, z) ((x) ^ (y) ^ (z))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

void SHA1::PaddingTheMessage() {
	union Transformation {
		uint8_t BytesOfNumber[8];
		uint64_t qwNumber;
	};
	Transformation transformationNumbers;

	uint64_t qwInputMessageSize = byarrMessage->size();

	byarrMessage->push_back(0x80);

	/*Add Bytes 0x00 in Massage to resolve equation : [InputMessageSize + 1 + NumberOfBytes0x00 = 56(mod 64)] <=> [l + 1 + k = 448(mod 512)]*/
	while(byarrMessage->size() % 64 != 56){ byarrMessage->push_back(0x00); }

	/*Add Block 64 bit Number of Bits InputMessageSize*/
	transformationNumbers.qwNumber = 8 * qwInputMessageSize;
	for (int i = 7; i > -1; i--) { byarrMessage->push_back(transformationNumbers.BytesOfNumber[i]); }
};

void SHA1::Preprocessing() {
	 PaddingTheMessage();
};

void SHA1::HashCompulation() {

	H0 = 0x67452301;
	H1 = 0xefcdab89;
	H2 = 0x98badcfe;
	H3 = 0x10325476;
	H4 = 0xc3d2e1f0;

	union FormatedMessageToAlgorithm {
		uint32_t M;
		uint8_t ByteArrayOfM[4];
	};
	FormatedMessageToAlgorithm formatMessage;

	for (register uint64_t i = 0; i < byarrMessage->size(); ) {
		while (M->size() != 16) {
			for (int j = 3; j > -1; j--) {
				#pragma warning (disable: 4244)
				formatMessage.ByteArrayOfM[j] = (*byarrMessage)[i];
				#pragma warning (default: 4244)
				i++;
			}
			M->push_back(formatMessage.M);
		}
		HashComplulationBlock();
		M->clear();
	}
};

void SHA1::HashComplulationBlock() {
	for (uint8_t t = 0; t < 16; t++) { W->push_back((*M)[t]); }
	for (uint8_t t = 16; t < 80; t++) { W->push_back(ROTL(((*W)[t - 3] ^ (*W)[t - 8] ^ (*W)[t - 14] ^ (*W)[t - 16]), 1)); }

	uint32_t a, b, c, d, e, f, T, K;
	a = H0;
	b = H1;
	c = H2;
	d = H3;
	e = H4;

	for (uint8_t t = 0; t < 80; t++) {

		if (t < 20) {
			f = Ch(b, c, d);
			K = K0;
		}
		else if (t < 40) {
			f = Parity(b, c, d);
			K = K1;
		}
		else if (t < 60) {
			f = Maj(b, c, d);
			K = K2;
		}
		else {
			f = Parity(b, c, d);
			K = K3;
		}

		T = ROTL(a, 5) + f + e + K + (*W)[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;
	}

	H0 += a;
	H1 += b;
	H2 += c;
	H3 += d;
	H4 += e;

	W->clear();
};

uint32_t SHA1::ROTL(uint32_t x, uint8_t n) { return ((x << n) | (x >> 32 - n)); };

vector<uint8_t>* SHA1::GetHash(vector<uint8_t>* ptrMessage) {

	byarrMessage = ptrMessage;
	M = make_unique<vector<uint32_t>>();
	W = make_unique<vector<uint32_t>>();

	Preprocessing();
	HashCompulation();

	union DigestFormat {
		uint32_t dwH;
		uint8_t byArray[4];
	};
	DigestFormat formatDigest;

	auto Digest = new vector<uint8_t>;

	formatDigest.dwH = H0;
	for (int i = 3; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.dwH = H1;
	for (int i = 3; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.dwH = H2;
	for (int i = 3; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.dwH = H3;
	for (int i = 3; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.dwH = H4;
	for (int i = 3; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }

	H0 = H1 = H2 = H3 = H4 = 0;

	return Digest;
};
