#pragma once

#include <iostream>

#include "ttmath/ttmath.h"
#include "ttmath/ttmathint.h"

using namespace std;

using bigint = ttmath::Int<64>;

class Miller_Rabin {

public:
	bigint mulmod(bigint a, bigint b, bigint mod)
	{
		bigint x = 0, y = a % mod;
		while (b > 0)
		{
			if (b % 2 == 1)
			{
				x = (x + y) % mod;
			}
			y = (y * 2) % mod;
			b /= 2;
		}
		return x % mod;
	}
	/*
	* modular exponentiation
	*/
	bigint modulo(bigint base, bigint exponent, bigint mod)
	{
		bigint x = 1;
		bigint y = base;
		while (exponent > 0)
		{
			if (exponent % 2 == 1)
				x = (x * y) % mod;
			y = (y * y) % mod;
			exponent = exponent / 2;
		}
		return x % mod;
	}

	/*
	* Miller-Rabin primality test, iteration signifies the accuracy
	*/
	bool Miller(bigint p, int iteration)
	{
		if (p < 2)
		{
			return false;
		}
		if (p != 2 && p % 2 == 0)
		{
			return false;
		}
		bigint s = p - 1;
		while (s % 2 == 0)
		{
			s /= 2;
		}
		for (int i = 0; i < iteration; i++)
		{
			bigint a = bigint(rand()) % (p - 1) + 1, temp = s;
			bigint mod = modulo(a, temp, p);
			while (temp != p - 1 && mod != 1 && mod != p - 1)
			{
				mod = mulmod(mod, mod, p);
				temp *= 2;
			}
			if (mod != p - 1 && temp % 2 == 0)
			{
				return false;
			}
		}
		return true;
	}
};