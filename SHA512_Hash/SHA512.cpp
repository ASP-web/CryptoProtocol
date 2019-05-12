#include "SHA512.h"

using namespace AlgorithmSHA512;

#define Ch(x, y, z) (((x) & (y)) ^ ((~x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

uint64_t K[80]{
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

uint64_t SHA512::ROTR(uint64_t x, uint8_t n) { return ((x >> n) | (x << (64 - n))); };

uint64_t SHA512::SHR(uint64_t x, uint8_t n) { return (x >> n); };

uint64_t SHA512::SIGMA0(uint64_t x) { return (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39)); };

uint64_t SHA512::SIGMA1(uint64_t x) { return (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)); };

uint64_t SHA512::sigma0(uint64_t x) { return (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7)); };

uint64_t SHA512::sigma1(uint64_t x) { return (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6)); };

void SHA512::PaddingTheMessage() {
	union Transformation {
		uint8_t BytesOfNumber[8];
		uint64_t qwNumber;
	};
	Transformation transformationNumbers;

	uint64_t qwInputMessageSize = byarrMessage->size();

	byarrMessage->push_back(0x80);

	/*Add Bytes 0x00 in Massage to resolve equation : [InputMessageSize + 1 + NumberOfBytes0x00 = 112(mod 128)] <=> [l + 1 + k = 896(mod 1024)]*/
	while (byarrMessage->size() % 128 != 112) { byarrMessage->push_back(0x00); }
	/*Add 8 bytes (64 bits) 0x00 because the length of input message is less 2^64 bits*/
	for (uint8_t i = 0; i < 8; i++){ byarrMessage->push_back(0x00); }
	/*Add Block 64 bit Number of Bits InputMessageSize*/
	transformationNumbers.qwNumber = 8 * qwInputMessageSize;
	for (int i = 7; i > -1; i--) { byarrMessage->push_back(transformationNumbers.BytesOfNumber[i]); }
};

void SHA512::Preprocessing() {
	PaddingTheMessage();
};

void SHA512::HashCompulation() {

	H0 = 0x6a09e667f3bcc908;
	H1 = 0xbb67ae8584caa73b;
	H2 = 0x3c6ef372fe94f82b;
	H3 = 0xa54ff53a5f1d36f1;
	H4 = 0x510e527fade682d1;
	H5 = 0x9b05688c2b3e6c1f;
	H6 = 0x1f83d9abfb41bd6b;
	H7 = 0x5be0cd19137e2179;

	union FormatedMessageToAlgorithm {
		uint64_t M;
		uint8_t ByteArrayOfM[8];
	};
	FormatedMessageToAlgorithm formatMessage;

	for (register uint64_t i = 0; i < byarrMessage->size(); ) {
		while (M->size() != 16) {
			for (int j = 7; j > -1; j--) {
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

void SHA512::HashComplulationBlock() {
	for (uint8_t t = 0; t < 16; t++) { W->push_back((*M)[t]); }
	for (uint8_t t = 16; t < 80; t++) { W->push_back(sigma1((*W)[t - 2]) + (*W)[t - 7] + sigma0((*W)[t - 15]) + (*W)[t - 16]); }

	uint64_t a, b, c, d, e, f, g, h , T1, T2;
	a = H0;
	b = H1;
	c = H2;
	d = H3;
	e = H4;
	f = H5;
	g = H6;
	h = H7;

	for (uint8_t t = 0; t < 80; t++) {
		T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + (*W)[t];
		T2 = SIGMA0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	H0 += a;
	H1 += b;
	H2 += c;
	H3 += d;
	H4 += e;
	H5 += f;
	H6 += g;
	H7 += h;


	W->clear();
};

vector<uint8_t>* SHA512::GetHash(vector<uint8_t>* ptrMessage) {

	byarrMessage = ptrMessage;
	M = make_unique<vector<uint64_t>>();
	W = make_unique<vector<uint64_t>>();

	Preprocessing();
	HashCompulation();

	union DigestFormat {
		uint64_t qwH;
		uint8_t byArray[8];
	};
	DigestFormat formatDigest;

	auto Digest = new vector<uint8_t>;

	formatDigest.qwH = H0;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H1;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H2;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H3;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H4;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H5;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H6;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }
	formatDigest.qwH = H7;
	for (int i = 7; i > -1; i--) { Digest->push_back(formatDigest.byArray[i]); }

	H0 = H1 = H2 = H3 = H4 = H5 = H6 = H7 = 0;

	return Digest;
};
