#include "RSA.h"
#include <fstream>

const uint8_t hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

string RSA::hexStr(vector<uint8_t>* data) {
	string s(data->size() * 2, ' ');
	for (register uint32_t i = 0; i < data->size(); ++i) {
		s[2 * i] = hexmap[((*data)[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[(*data)[i] & 0x0F];
	}
	return s;
};

void RSA::GeneratePrimeParametr_p()
{
	auto PRN = generatorPRN.GeneratePRN(10);
	p.FromString(hexStr(PRN), 16);
	if (p < 0) p *= -1;
	delete PRN;

	//cout << atkin4.PrimeArray[1] << endl;
	while (!/*isPrime_SmallFermaTeorem*/isprime(p)) { p += 1; }
	cout << p.ToString() << endl;
}

bool RSA::isPrime_SmallFermaTeorem(bigint n)
{
	//if (n % 2 == 0) return false;
	//for (uint32_t i = 0; i < atkin4.PrimeArray.size(); i++) {
	//	if (n % atkin4.PrimeArray[i] == 0) return false;
	//}
	return true;
}
