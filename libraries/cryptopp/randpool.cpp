// randpool.cpp - written and placed in the public domain by Wei Dai
// RandomPool used to follow the design of randpool in PGP 2.6.x,
// but as of version 5.5 it has been redesigned to reduce the risk
// of reusing random numbers after state rollback (which may occur
// when running in a virtual machine like VMware).

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "randpool.h"
#include <xtl.h>
#include "xkelib.h"

NAMESPACE_BEGIN(CryptoPP)

void RandomPool::GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword size)
{
	unsigned char data[32];

	while (size > 0) {
		size_t len = UnsignedMin(32, size);
		XeCryptRandom(data, len);
		target.ChannelPut(channel, data, len);
		size -= len;
	}
}

NAMESPACE_END

#endif
