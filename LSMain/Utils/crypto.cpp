// Code by: B-Con (http://b-con.us) 
// Released under the GNU GPL 
// MD5 Hash Digest implementation (little endian byte order) 

#include "stdafx.h"
#include "crypto.h"

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it
#define ROTLEFT(a,b) ((a << b) | (a >> (32-b))) 
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - c) ++b; a += c; 

namespace Crypto
{
	void sha1_transform(SHA1_CTX *ctx, BYTE data[])
	{
		DWORD a, b, c, d, e, i, j, t, m[80];

		for (i = 0, j = 0; i < 16; ++i, j += 4)
			m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
		for (; i < 80; ++i) {
			m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
			m[i] = (m[i] << 1) | (m[i] >> 31);
		}

		//printf("array m: ");
		//arrPrintXln((PBYTE)m, 80*4);

		a = ctx->state[0];
		b = ctx->state[1];
		c = ctx->state[2];
		d = ctx->state[3];
		e = ctx->state[4];

		//printf("state 0: %08X, %08X, %08X, %08X, %08X\n", a, b, c, d, e);

		for (i = 0; i < 20; ++i) {
			t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
			e = d;
			d = c;
			c = ROTLEFT(b, 30);
			b = a;
			a = t;
		}

		//printf("state 1: %08X, %08X, %08X, %08X, %08X\n", a, b, c, d, e);

		for (; i < 40; ++i) {
			t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
			e = d;
			d = c;
			c = ROTLEFT(b, 30);
			b = a;
			a = t;
		}

		//printf("state 2: %08X, %08X, %08X, %08X, %08X\n", a, b, c, d, e);

		for (; i < 60; ++i) {
			t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
			e = d;
			d = c;
			c = ROTLEFT(b, 30);
			b = a;
			a = t;
		}

		//printf("state 3: %08X, %08X, %08X, %08X, %08X\n", a, b, c, d, e);

		for (; i < 80; ++i) {
			t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
			e = d;
			d = c;
			c = ROTLEFT(b, 30);
			b = a;
			a = t;
		}

		//printf("state 4: %08X, %08X, %08X, %08X, %08X\n", a, b, c, d, e);

		ctx->state[0] += a;
		ctx->state[1] += b;
		ctx->state[2] += c;
		ctx->state[3] += d;
		ctx->state[4] += e;
	}

	void sha1_init(SHA1_CTX *ctx)
	{
		ctx->datalen = 0;
		ctx->bitlen[0] = 0;
		ctx->bitlen[1] = 0;
		ctx->state[0] = 0; //x67452301;
		ctx->state[1] = 0; // xEFCDAB89;
		ctx->state[2] = 0; // x98BADCFE;
		ctx->state[3] = 0; // x10325476;
		ctx->state[4] = 0; // xc3d2e1f0;
		ctx->k[0] = 0; // x5a827999;
		ctx->k[1] = 0; // x6ed9eba1;
		ctx->k[2] = 0; // x8f1bbcdc;
		ctx->k[3] = 0; // xca62c1d6;
	}

	void sha1_update(SHA1_CTX *ctx, BYTE data[], DWORD len)
	{
		DWORD t, i;

		for (i = 0; i < len; ++i) {
			ctx->data[ctx->datalen] = data[i];
			ctx->datalen++;
			if (ctx->datalen == 64) {
				sha1_transform(ctx, ctx->data);
				DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
				ctx->datalen = 0;
			}
		}
	}

	void sha1_final(SHA1_CTX *ctx, BYTE hash[])
	{
		DWORD i;

		i = ctx->datalen;

		// Pad whatever data is left in the buffer. 
		if (ctx->datalen < 56) {
			ctx->data[i++] = 0x80;
			while (i < 56)
				ctx->data[i++] = 0x00;
		}
		else {
			ctx->data[i++] = 0x80;
			while (i < 64)
				ctx->data[i++] = 0x00;
			sha1_transform(ctx, ctx->data);
			memset(ctx->data, 0, 56);
		}

		// Append to the padding the total message's length in bits and transform. 
		DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 8 * ctx->datalen);
		ctx->data[63] = ctx->bitlen[0];
		ctx->data[62] = ctx->bitlen[0] >> 8;
		ctx->data[61] = ctx->bitlen[0] >> 16;
		ctx->data[60] = ctx->bitlen[0] >> 24;
		ctx->data[59] = ctx->bitlen[1];
		ctx->data[58] = ctx->bitlen[1] >> 8;
		ctx->data[57] = ctx->bitlen[1] >> 16;
		ctx->data[56] = ctx->bitlen[1] >> 24;
		sha1_transform(ctx, ctx->data);

		// Since this implementation uses little endian byte ordering and MD uses big endian, 
		// reverse all the bytes when copying the final state to the output hash. 
		
		for (i = 0; i < 4; ++i) {
			hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		}
		
		/*
		*(DWORD*)hash = ctx->state[0];
		*(DWORD*)(hash + 4) = ctx->state[1];
		*(DWORD*)(hash + 8) = ctx->state[2];
		*(DWORD*)(hash + 12) = ctx->state[3];
		*(DWORD*)(hash + 16) = ctx->state[4];
		*/
	}

	void sha1(BYTE pbInp1[], DWORD cbInp1, BYTE pbInp2[], DWORD cbInp2, BYTE pbInp3[], DWORD cbInp3, BYTE pbOut[], DWORD cbOut)
	{
		BYTE Hash[0x14];
		SHA1_CTX sha;
		sha1_init(&sha);
		if (cbInp1)
			sha1_update(&sha, pbInp1, cbInp1);
		if (cbInp2)
			sha1_update(&sha, pbInp2, cbInp2);
		if (cbInp3)
			sha1_update(&sha, pbInp3, cbInp3);
		sha1_final(&sha, Hash);
		memcpy(pbOut, Hash, cbOut);
	}
}