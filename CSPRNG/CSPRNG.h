#ifndef CSPRNG_H
#define CSPRNG_H

#include <iostream>
#include <vector>

using namespace std;

class CSPRNG {
public:
	vector<uint8_t>* GeneratePRN(uint64_t PRNSizeInBytes);
};


#endif //CSPRNG_H