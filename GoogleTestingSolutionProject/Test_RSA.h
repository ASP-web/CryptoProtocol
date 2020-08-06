#pragma once

#include "../RSA/RSA.h"
#include "gtest/gtest.h"
#include <string>
#include <chrono>

/*Unit Test SHA512 Hash Algorithm*/
class RSATest : public ::testing::Test {
public:
	RSA* rInstance{ nullptr };
	using myclock = chrono::steady_clock;
	myclock::time_point start;
	myclock::time_point end;

protected:
	void SetUp() override {
		rInstance = new RSA;
	}

	void TearDown() override { delete rInstance; }
};

TEST_F(RSATest, RSA_TEST) {
	rInstance->GeneratePrimeParametr_p();
}