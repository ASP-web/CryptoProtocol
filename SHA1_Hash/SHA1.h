#ifndef SHA1_H
#define SHA1_H

#include <iostream>
#include <cstring>
#include <assert.h>
typedef unsigned int uint32;
using namespace std;

class SHA1
{
private:
	uint32 H0, H1, H2, H3, H4;
	unsigned char bytes[64];
	int unprocessedBytes;
	uint32 size;
	void process();
public:
	SHA1();
	~SHA1();
	void addBytes(const char* data, int num);
	unsigned char* getDigest();
	static uint32 ROTL(uint32 x, int bits);
	static void uint32_to_uchar(unsigned char* byte, uint32 num);
};



uint32 SHA1::ROTL(uint32 x, int bits)
{
	return (x << bits) | (x >> (32 - bits));
};


void SHA1::uint32_to_uchar(unsigned char* byte, uint32 num)
{
	assert(byte);
	byte[0] = (unsigned char)(num >> 24);
	byte[1] = (unsigned char)(num >> 16);
	byte[2] = (unsigned char)(num >> 8);
	byte[3] = (unsigned char)num;
}


// Constructor *******************************************************
SHA1::SHA1()
{
	// проверка на корректность типа uint32
	assert(sizeof(uint32) * 5 == 20);

	// начальные данные
	H0 = 0x67452301;
	H1 = 0xefcdab89;
	H2 = 0x98badcfe;
	H3 = 0x10325476;
	H4 = 0xc3d2e1f0;
	unprocessedBytes = 0;
	size = 0;
}

// Destructor ********************************************************
SHA1::~SHA1()
{
	// данные на выходе
	H0 = H1 = H2 = H3 = H4 = 0;
	for (int c = 0; c < 64; c++) bytes[c] = 0;
	unprocessedBytes = size = 0;
}

// process ***********************************************************
void SHA1::process()
{
	assert(unprocessedBytes == 64);

	int t;
	uint32 a, b, c, d, e, K, f, W[80];

	a = H0;
	b = H1;
	c = H2;
	d = H3;
	e = H4;
	/*–асширение*/
	for (t = 0; t < 16; t++) { W[t] = (bytes[t * 4] << 24) + (bytes[t * 4 + 1] << 16) + (bytes[t * 4 + 2] << 8) + bytes[t * 4 + 3]; }
	for (; t < 80; t++) { W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1); }

	/*—жатие */
	uint32 temp;
	for (t = 0; t < 80; t++)
	{
		if (t < 20) {
			K = 0x5a827999;
			f = (b & c) ^ ((~b) & d);
		}
		else if (t < 40) {
			K = 0x6ed9eba1;
			f = b ^ c ^ d;
		}
		else if (t < 60) {
			K = 0x8f1bbcdc;
			f = (b & c) ^ (b & d) ^ (c & d);
		}
		else {
			K = 0xca62c1d6;
			f = b ^ c ^ d;
		}
		temp = ROTL(a, 5) + f + e + W[t] + K;
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = temp;
	}
	/* —уммирование */
	H0 += a;
	H1 += b;
	H2 += c;
	H3 += d;
	H4 += e;

	unprocessedBytes = 0;
}

// addBytes **********************************************************
void SHA1::addBytes(const char* data, int num)
{
	assert(data);
	assert(num > 0);

	size += num;

	while (num > 0)
	{

		int needed = 64 - unprocessedBytes;
		assert(needed > 0);
		// число байт дл€ копировани€ в 512 битовый блок
		int toCopy = (num < needed) ? num : needed;
		// копирование байт
		memcpy(bytes + unprocessedBytes, data, toCopy);

		num -= toCopy;
		data += toCopy;
		unprocessedBytes += toCopy;

		// проверка на полноту блока (512бит==64байта)
		if (unprocessedBytes == 64) process();
	}
}

// digest ************************************************************
unsigned char* SHA1::getDigest()
{
	// ’ранение длины сообщени€
	uint32 totalBitsL = size << 3;
	uint32 totalBitsH = size >> 29;
	// добавление 0x80 в последний некратный блок
	addBytes("\x80", 1);

	//массив, в котором хранитс€ последний-дополненный блок
	unsigned char footer[64] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	if (unprocessedBytes > 56)
		addBytes((char*)footer, 64 - unprocessedBytes);
	assert(unprocessedBytes <= 56);
	// сколько нулей нужно добавить после '1'
	int neededZeros = 56 - unprocessedBytes;
	// хранение размера сообщени€ max(64 бит) в конце массива footer(512)
	uint32_to_uchar(footer + neededZeros, totalBitsH);
	uint32_to_uchar(footer + neededZeros + 4, totalBitsL);
	// окончание формировани€ последнего (дополненного) блока
	addBytes((char*)footer, neededZeros + 8);
	// хранение дайджаста (хэш-значени€) сообщени€
	unsigned char* digest = new unsigned char[20];
	// копирование дайджаста из unsigned int -> unsigned char
	uint32_to_uchar(digest, H0);
	uint32_to_uchar(digest + 4, H1);
	uint32_to_uchar(digest + 8, H2);
	uint32_to_uchar(digest + 12, H3);
	uint32_to_uchar(digest + 16, H4);
	// return digest
	return digest;
}

#endif //SHA1_H
