#pragma once

#include <iostream>

using namespace std;

class Atkin4 {
		uint32_t MAX = 1000000000;
		uint32_t SQRT_MAX = (uint32_t)sqrt(MAX) + 1;
		uint32_t MEMORY_SIZE = MAX >> 4;

public:
		uint8_t* Array;
		vector<uint32_t> PrimeArray;
public:
	Atkin4() {
		Array = new uint8_t[MEMORY_SIZE];
		GeneratePrimes();
	}

private:
	 void GeneratePrimes() {
		// Find prime
		int sequence[] = { 2, 4 };
		int index = 0;
		uint32_t k1 = 0, k = 0;

		double xUpper = sqrt(MAX / 4) + 1;
		uint32_t x = 1;
		uint32_t y = 0;

		while (x < xUpper) {
			index = 0;
			k1 = 4 * x * x;
			y = 1;
			if (x % 3 == 0) {
				while (true) {
					k = k1 + y * y;
					if (k >= MAX) {
						break;
					}
					toggleBit(k);
					y += sequence[(++index & 1)];
				}
			}
			else {
				while (true) {
					k = k1 + y * y;
					if (k >= MAX) {
						break;
					}
					toggleBit(k);
					y += 2;
				}
			}
			x++;
		}

		xUpper = sqrt(MAX / 3) + 1;
		x = 1;
		y = 0;

		while (x < xUpper) {
			index = 1;
			k1 = 3 * x * x;
			y = 2;
			while (true) {
				k = k1 + y * y;
				if (k >= MAX) {
					break;
				}
				toggleBit(k);
				y += sequence[(++index & 1)];
			}
			x += 2;
		}

		xUpper = sqrt(MAX);
		x = 1;
		y = 0;

		while (x < xUpper) {
			k1 = 3 * x * x;
			if ((x & 1) == 0) {
				y = 1;
				index = 0;
			}
			else {
				y = 2;
				index = 1;
			}
			while (y < x) {
				k = k1 - y * y;
				if (k < MAX) {
					toggleBit(k);
				}
				y += sequence[(++index & 1)];
			}
			x++;
		}

		setBit(2);
		setBit(3);
		for (uint32_t n = 5; n <= SQRT_MAX; n += 2) {
			if (getBit(n)) {
				uint32_t n2 = n * n;
				for (k = n2; k < MAX; k += (2 * n2)) {
					unSetBit(k);
				}
			}
		}

		// Display prime
		uint32_t pi = 0;
		for (uint32_t i = 3; i < MAX; i += 2) {
			if (getBit(i)) {
				pi++;
				PrimeArray.push_back(i);
				//cout << i << endl;
			}
		}
	}

	bool getBit(uint32_t i) {
		uint8_t block = Array[(int)(i >> 4)];
		uint8_t mask = (1 << ((i >> 1) & 7));

		return ((block & mask) != 0);
	}

	void setBit(uint32_t i) {
		uint32_t index = (i >> 4);
		uint8_t block = Array[index];
		uint8_t mask = (1 << ((i >> 1) & 7));

		Array[index] = (block | mask);
	}

	void unSetBit(uint32_t i) {
		uint32_t index = (int)(i >> 4);
		uint8_t block = Array[index];
		uint8_t mask = (1 << ((i >> 1) & 7));

		Array[index] = (block & ~mask);
	}

	void toggleBit(uint32_t i) {
		uint32_t index = (int)(i >> 4);
		uint8_t block = Array[index];
		uint8_t mask = (1 << ((i >> 1) & 7));

		Array[index] = (block ^ mask);
	}
};