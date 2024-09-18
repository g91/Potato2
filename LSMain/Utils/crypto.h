#pragma once

#include "stdafx.h"

// Signed variables are for wimps 
#define BYTE unsigned char 
#define uint unsigned int 

namespace Crypto
{
	typedef struct {
		BYTE data[64];
		DWORD datalen;
		DWORD bitlen[2];
		DWORD state[5];
		DWORD k[4];
	} SHA1_CTX;

	void sha1_init(SHA1_CTX *ctx);
	void sha1_update(SHA1_CTX *ctx, BYTE data[], DWORD len);
	void sha1_final(SHA1_CTX *ctx, BYTE hash[]);
	void sha1_transform(SHA1_CTX *ctx, BYTE data[]);
	void sha1(BYTE pbInp1[], DWORD cbInp1, BYTE pbInp2[], DWORD cbInp2, BYTE pbInp3[], DWORD cbInp3, BYTE pbOut[], DWORD cbOut);
}