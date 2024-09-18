#include "stdafx.h"
#include "Exports.h"
#include "Dump.h"
#include "crypto.h"
#include "soc.h"

// delete later, messy code
#define DEVICE_60000 0x8000020000060000 // r16
#define DEVICE_60B58 0x8000020000060B58
#define DEVICE_61000 0x8000020000061000 // r30
#define DEVICE_61188 0x8000020000061188
#define DEVICE_61030 0x8000020000061030
#define DEVICE_61050 0x8000020000061050
#define DEVICE_61060 0x8000020000061060
#define DEVICE_50000 0x8000020000050000 // r24
#define DEVICE_56020 0x8000020000056020
#define DEVICE_50008 0x8000020000050008
#define DEVICE_50050 0x8000020000050050
#define DEVICE_50060 0x8000020000050060
#define DEVICE_30000 0x8000020000030000 // r18
#define DEVICE_37000 0x8000020000037000
#define DEVICE_30010 0x8000020000030010
#define DEVICE_30020 0x8000020000030020
#define DEVICE_48000 0x8000020000048000 // r19
#define DEVICE_0E102 0x80000200E1020000 // r29
#define DEVICE_0E102_0004 0x80000200E1020004
#define DEVICE_0E100 0x80000200E1000000 // r17
#define DEVICE_0E100_7000 0x80000200E1007000

BYTE pbFuncPayload[0xEC] = {
	0x7D, 0x88, 0x02, 0xA6, 0xF9, 0x81, 0xFF, 0xF8, 0xFB, 0xE1, 0xFF, 0xF0, 0xFB, 0xC1, 0xFF, 0xE8,
	0xFB, 0xA1, 0xFF, 0xE0, 0xFB, 0x81, 0xFF, 0xD8, 0xFB, 0x61, 0xFF, 0xD0, 0xFB, 0x41, 0xFF, 0xC8,
	0xFB, 0x21, 0xFF, 0xC0, 0xFB, 0x01, 0xFF, 0xB8, 0xFA, 0xE1, 0xFF, 0xB0, 0xF8, 0x21, 0xFF, 0x11,
	0x7C, 0x89, 0x03, 0xA6, 0x7C, 0xA3, 0x2B, 0x78, 0x7C, 0xC4, 0x33, 0x78, 0x7C, 0xE5, 0x3B, 0x78,
	0x4E, 0x80, 0x04, 0x21, 0x38, 0x21, 0x00, 0xF0, 0xE9, 0x81, 0xFF, 0xF8, 0xEA, 0xE1, 0xFF, 0xB0,
	0xEB, 0x01, 0xFF, 0xB8, 0xEB, 0x21, 0xFF, 0xC0, 0xEB, 0x41, 0xFF, 0xC8, 0xEB, 0x61, 0xFF, 0xD0,
	0xEB, 0x81, 0xFF, 0xD8, 0xEB, 0xA1, 0xFF, 0xE0, 0xEB, 0xC1, 0xFF, 0xE8, 0xEB, 0xE1, 0xFF, 0xF0,
	0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20, 0x7C, 0xA9, 0x03, 0xA6, 0x38, 0x84, 0xFF, 0xFF,
	0x38, 0x63, 0xFF, 0xFF, 0x8C, 0xA4, 0x00, 0x01, 0x9C, 0xA3, 0x00, 0x01, 0x42, 0x00, 0xFF, 0xF8,
	0x4E, 0x80, 0x00, 0x20, 0x7C, 0x7E, 0x1B, 0x78, 0x7C, 0x8B, 0x23, 0x78, 0x7D, 0x69, 0x03, 0xA6,
	0x88, 0x7E, 0x00, 0x00, 0x3C, 0x80, 0x80, 0x00, 0x60, 0x84, 0x02, 0x00, 0x78, 0x84, 0x07, 0xC6,
	0x64, 0x84, 0xEA, 0x00, 0x80, 0xA4, 0x10, 0x18, 0x54, 0xA5, 0x01, 0x8D, 0x41, 0x82, 0xFF, 0xF8,
	0x54, 0x63, 0xC0, 0x0E, 0x90, 0x64, 0x10, 0x14, 0x3B, 0xDE, 0x00, 0x01, 0x42, 0x00, 0xFF, 0xD4,
	0x4E, 0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void testFuses()
{
	QWORD arg1;
	QWORD arg2;
	QWORD arg3;

}

void dumpHardwareRegs()
{
	printf("[%016llX]: %016llX\n", DEVICE_60B58, Hvx::HvPeekQWORD(DEVICE_60B58));
	printf("[%016llX]: %016llX\n", DEVICE_61030, Hvx::HvPeekQWORD(DEVICE_61030));
	printf("[%016llX]: %016llX\n", DEVICE_61050, Hvx::HvPeekQWORD(DEVICE_61050));
	printf("[%016llX]: %016llX\n", DEVICE_61060, Hvx::HvPeekQWORD(DEVICE_61060));
	printf("[%016llX]: %016llX\n", DEVICE_61188, Hvx::HvPeekQWORD(DEVICE_61188));
	printf("[%016llX]: %016llX\n", DEVICE_50008, Hvx::HvPeekQWORD(DEVICE_50008));
	printf("[%016llX]: %016llX\n", DEVICE_50050, Hvx::HvPeekQWORD(DEVICE_50050));
	printf("[%016llX]: %016llX\n", DEVICE_50060, Hvx::HvPeekQWORD(DEVICE_50060));
	printf("[%016llX]: %016llX\n", DEVICE_56020, Hvx::HvPeekQWORD(DEVICE_56020));
	printf("[%016llX]: %016llX\n", DEVICE_30010, Hvx::HvPeekQWORD(DEVICE_30010));
	printf("[%016llX]: %016llX\n", DEVICE_30020, Hvx::HvPeekQWORD(DEVICE_30020));
	printf("[%016llX]: %016llX\n", DEVICE_37000, Hvx::HvPeekQWORD(DEVICE_37000));
	printf("[%016llX]: %016llX\n", DEVICE_48000, Hvx::HvPeekQWORD(DEVICE_48000));
	printf("[%016llX]: %016llX\n", DEVICE_0E100_7000, Hvx::HvPeekQWORD(DEVICE_0E100_7000));
	printf("[%016llX]: %08X\n", DEVICE_0E102_0004, Hvx::HvPeekDWORD(DEVICE_0E102_0004));
}

// To get SRAM address from Protected Address :
#define ProtToSRAM(addy) (SPACE_SRAM + ((addy >> 6) & 0x3FF) | ((addy >> 23) & 0xFC00))
// To get the SRAM hash offset of an HV offset :
#define HvToSRAM(addy) (SPACE_SRAM + (addy >> 6) & 0x3FF)
// To get the HV offset of an SRAM hash offset :
#define SRAMToHv(addy) (SPACE_SRAM +(addy & 0x3FF) << 6)

typedef union _SECENG_FAULT_ISOLATION {
	QWORD AsULONGLONG; // 0x0 sz:0x8
	struct {
		QWORD IntegrityViolation : 1; // 0x0 bfo:0x63
		QWORD Reserved1 : 63; // 0x0 bfo:0x0
	}AsBits;
} SECENG_FAULT_ISOLATION, *PSECENG_FAULT_ISOLATION;

void MakeHvHashes(QWORD qwHvAddress, DWORD cCount)
{
	if ((cCount << 7) > 0x10000)
		return;

	DWORD szCacheBlock = 0x80;
	DWORD cbBytes = cCount << 7;
	DWORD szCacheBlockCount = cCount;
	DWORD cbHashes = cCount << 1;

	QWORD qwHvAddy = qwHvAddress;
	QWORD qwHvSRAM = ProtToSRAM(qwHvAddy);
	PBYTE pbHvBuf = (PBYTE)XPhysicalAllocM(cbBytes);
	ZeroMemory(pbHvBuf, cbBytes);
	Hvx::HvPeekBytes(qwHvAddy, pbHvBuf, cbBytes);
	printf("HV Address: %016llX, HV SRAM Address: %016llX, Bytes: %X, Cacheline Count: %X\n", qwHvAddy, qwHvSRAM, cbBytes, szCacheBlockCount);
	PBYTE pbHvHashes = (PBYTE)XPhysicalAllocM(cbHashes);
	ZeroMemory(pbHvHashes, cbHashes);
	Hvx::HvPeekBytes(qwHvSRAM, pbHvHashes, cbHashes);
	printf("HV Hashes (first 16 bytes): ");
	arrPrintXln(pbHvHashes, 0x10);

	BYTE bBufKey = 0x3B;
	PBYTE pbBuf = (PBYTE)XPhysicalAlloc(cbBytes, MAXULONG_PTR, 0x10000, PAGE_READWRITE);
	ZeroMemory(pbBuf, cbBytes);
	QWORD pbBufReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(pbBuf);
	QWORD pbBufProt = Hvx::HvProc(Hvx::HvpRelocatePhysicalToProtected, 3, pbBufReal, cbBytes, bBufKey);
	QWORD pbBufSRAM = ProtToSRAM(pbBufProt);
	printf("Buffer Real Address: %016llX, Buffer Protected Address: %016llX, Buffer SRAM Address: %016llX, Buffer Key: %X\n", pbBufReal, pbBufProt, pbBufSRAM, bBufKey);
	Hvx::HvPokeBytes(pbBufProt, pbHvBuf, cbBytes);
	PBYTE pbBufHashes = (PBYTE)XPhysicalAllocM(cbHashes);
	ZeroMemory(pbBufHashes, cbHashes);
	Hvx::HvPeekBytes(pbBufSRAM, pbBufHashes, cbHashes);
	printf("Buf Hashes (first 16 bytes): ");
	arrPrintXln(pbBufHashes, 0x10);

	Hvx::HvProc(Hvx::HvpInvalidateCachelines, 2, pbBufProt, cbBytes);
	Hvx::HvProc(Hvx::HvpZeroCacheLines, 2, pbBufReal, szCacheBlockCount);

	XPhysicalFree(pbHvBuf);
	XPhysicalFree(pbBuf);
	XPhysicalFree(pbHvHashes);
	XPhysicalFree(pbBufHashes);
}

#define ROTL64(data, bits) ((data << (bits & 0x3F)) | data >> 64-(bits & 0x3F))
#define ROTR64(data, bits) ((data >> (bits & 0x3F)) | data << 64-(bits & 0x3F))
#define ROTL16(data, bits) ((((data & 0xFFFF) << (bits & 0xF)) | (data & 0xFFFF) >> 16-(bits & 0xF)) & 0xFFFF)
#define ROTR16(data, bits) ((((data & 0xFFFF) >> (bits & 0xF)) | (data & 0xFFFF) << 16-(bits & 0xF)) & 0xFFFF)
#define ROTL8(data, bits) ((((data & 0xFF) << (bits & 7)) | (data & 0xFF) >> 16-(bits & 7)) & 0xFF)
#define ROTR8(data, bits) ((((data & 0xFF) >> (bits & 7)) | (data & 0xFF) << 16-(bits & 7)) & 0xFF)

#define CRC_TYPE_IBM 0
#define CRC_TYPE_CCITT 1
// TODO: figure out if the normal polynomials are being used or if theyre derived from keys?
#define POLYNOMIAL_IBM 0xAAAA
#define POLYNOMIAL_CCITT 0
// TODO: figure out if normal seeds are being used or if theyre derived from keys?
#define CRC_IBM_SEED 0xFFFF
#define CRC_CCITT_SEED 0

void RadioComputeWhitening_IBM(PBYTE pbBuf, DWORD cbBuf)
{
	BYTE WhiteningKeyMSB = 1;
	BYTE WhiteningKeyLSB = 0xFF;
	BYTE WhiteningKeyMSBPrevious = 0;

	for (int i = 0; i < cbBuf; i++)
	{
		pbBuf[i] ^= WhiteningKeyLSB;

		for (int j = 0; j < 8; j++)
		{
			WhiteningKeyMSBPrevious = WhiteningKeyMSB;
			WhiteningKeyMSB = (WhiteningKeyLSB & 1) ^ ((WhiteningKeyLSB >> 5) & 1);
			WhiteningKeyLSB = ((WhiteningKeyLSB >> 1) & 0xFF) | ((WhiteningKeyMSBPrevious << 7) & 0x80);
		}
	}
}

WORD ComputeCRC(WORD wCRC, BYTE bData, WORD wPoly)
{
	for (int i = 0; i < 8; i++)
	{
		wCRC ^= bData;
		if (wCRC & 0x8000)
		{
			wCRC <<= 1;
			wCRC ^= wPoly;
		}
		else
			wCRC <<= 1;
	}

	return wCRC;
}

WORD RadioComputeCRC(PBYTE pbBuf, DWORD cbBuf, DWORD crcType = NULL)
{
	WORD wPoly = 0;
	WORD wCRC = 0;
	if (crcType == CRC_TYPE_IBM)
	{
		wPoly = POLYNOMIAL_IBM;
		wCRC = CRC_IBM_SEED;
	}
	else
	{
		wPoly = POLYNOMIAL_CCITT;
		wCRC = CRC_CCITT_SEED;
	}

	for (int i = 0; i < cbBuf; i++)
		wCRC = ComputeCRC(wCRC, pbBuf[i], wPoly);

	if (crcType != CRC_TYPE_IBM)
		wCRC = (~wCRC) & 0xFFFF;

	return wCRC;
}

int crc16(PBYTE addr, int num, int crc)
{

	for (int i = 0; i < num; i++)               /* Step through bytes in memory */
	{
		crc = crc ^ (addr[i] << 8);      /* Fetch byte from memory, XOR into CRC top byte*/
		for (int j = 0; j<8; j++)              /* Prepare to rotate 8 bits */
		{
			crc = crc << 1;                /* rotate */
			if (crc & 0x10000)             /* bit 15 was set (now bit 16)... */
				crc = (crc ^ POLYNOMIAL_IBM) & 0xFFFF; /* XOR with XMODEM polynomic */
													   /* and ensure CRC remains 16-bit value */
		}                              /* Loop for 8 bits */
	}                                /* Loop until num=0 */
	return(crc);                     /* Return updated CRC */
}

// assumes Buffer is 128 bytes in length

#define SoCHash SoCHashBy16

// SoC Hashing words (no key)
WORD SoCHashBy16(PVOID Buffer)
{
	WORD wHash = 0;
	BYTE rotl = 15;
	for (int i = 0; i < 16; i++)
	{
		QWORD qwData = ROTR64(((PQWORD)Buffer)[i], i + 1);
		//QWORD qwData = ROTL64(((PQWORD)Buffer)[i], rotl);
		for (int j = 0; j < 4; j++)
			wHash ^= ((PWORD)&qwData)[j];
		rotl--;
	}
	return wHash;
}

// SoC Hashing words (no key)
WORD SoCHashBy16A(PVOID Buffer)
{
	WORD wHash = 0;
	BYTE rotl = 15;
	for (int i = 0; i < 16; i++)
	{
		QWORD qwData = ((PQWORD)Buffer)[i];
		for (int j = 0; j < 4; j++)
		{
			WORD wData = ((PWORD)&qwData)[j];
			wData = ROTR16(wData, i + 1);
			wHash ^= wData;
		}
		rotl--;
	}
	return wHash;
}

// SoC Hashing bytes (no key)
WORD SoCHashBy8(PVOID Buffer)
{
	WORD wHash = 0;
	BYTE rotl = 15;
	for (int i = 0; i < 16; i++)
	{
		QWORD qwData = ROTR64(((PQWORD)Buffer)[i], i+1);
		for (int j = 0; j < 8; j++)
			((PBYTE)&wHash)[j & 1] ^= ((PBYTE)&qwData)[j];
		rotl--;
	}
	return wHash;
}

WORD SoCHashTestA(PVOID Buffer, PVOID Key, BOOL dwLog = 0)
{
	WORD wHash = 0;
	WORD wHashData = 0;
	WORD wHashKey = 0;
	BYTE rotl = 15;
	QWORD pqwKey[2] = { ((PQWORD)Key)[0], ((PQWORD)Key)[1] };
	//QWORD qwKey = (ROTL64(pqwKey[0], 1)) ^ pqwKey[1];
	for (int i = 0; i < 16; i++)
	{
		wHashKey = 0;
		wHashData = 0;
		WORD wTmp = 0;

		QWORD qwData = ((PQWORD)Buffer)[i];
		//qwData = ROTR64(qwData, i+1);

		QWORD qwKey = pqwKey[i & 1];
		//qwKey = ROTR64(qwKey, i+1);

		qwData ^= qwKey;

		for (int j = 0; j < 4; j++)
		{
			WORD wData = ((PWORD)&qwData)[j];
			wData = ROTR16(wData, i + 1);
			wHashData ^= wData;

			WORD wKey = ((PWORD)&qwKey)[j];
			wKey = ROTR16(wKey, i + 1);
			wHashKey ^= wKey;

			//wHashData ^= wKey;

			if(dwLog)
				printf("[%d,%d] Data: %04X, Hash: %04X || Key: %04X, Hash: %04X\n", i, j, wData, wHashData, wKey, wHashKey);

			//wHash ^= wKey;
		}
		rotl--;

		//wHash ^= wHashKey;
		wHash ^= (wHashData);
		//wHash ^= wHashKey;
		if(dwLog)
			printf("[%d] Hash: %04X\n", i, wHash);
	}
	return (wHash);
}

// this is the best progress so far, but theres something wrong
// im pretty sure they do something on the final loop of the inner loop or outer loop
// maybe a final xor?

WORD SoCHashTest(PVOID Buffer, PVOID Key, DWORD dwFlags = 0)
{
	BOOL dwLog = dwFlags & 1;
	BOOL dwSwap = dwFlags & 2;

	WORD wHash = 0;
	WORD wHashData = 0;
	WORD wHashKey = 0;
	BYTE rotl = 15;
	QWORD pqwKey[2] = { ((PQWORD)Key)[0], ((PQWORD)Key)[1] };
	//QWORD qwKey = (ROTL64(pqwKey[0], 1)) ^ pqwKey[1];

	QWORD pqwData[16] = { 0 };
	for (int i = 0; i < 16; i++)
	{
		if (dwSwap)
			pqwData[i] = _byteswap_uint64(((PQWORD)Buffer)[i]);
		else
			pqwData[i] = ((PQWORD)Buffer)[i];
	}

	for (int i = 0; i < 16; i++)
	{
		//wHashKey = 0;
		wHashData = 0;
		WORD wTmp = 0;

		QWORD qwData = pqwData[i];
		qwData = ROTR64(qwData, i + 1);

		QWORD qwKey = pqwKey[i & 1];
		qwKey = ROTL64(qwKey, i + 1);

		//qwData ^= qwKey;

		for (int j = 0; j < 4; j++)
		{
			WORD wData = ((PWORD)&qwData)[j];
			//wData = ROTR16(wData, i + 1);

			WORD wKey = ((PWORD)&qwKey)[j];
			//wKey = ROTL16(wKey, i + 1);

			wData ^= wKey;
			wHashData ^= wData;
			wHashKey ^= wKey;

			//wHashData ^= wHashKey;

			if (dwLog)
				printf("[%d,%d] Data: %04X, Hash: %04X || Key: %04X, Hash: %04X\n", i, j, wData, wHashData, wKey, wHashKey);
		}
		rotl--;

		//wHash ^= wHashKey;
		wHash ^= (wHashData);
		wHash ^= wHashKey;

		if (dwLog)
			printf("[%d] Hash: %04X\n", i, wHash);
	}
	return (wHash);
}

namespace Exports
{
	void MiscTest()
	{
		printf("MiscTest\n");

		//Hvx::HvPokeDWORD(0x600030914, 0x38600000);
		printf("SDR1: %016llX\n", Hvx::HvPeekSPR(Hvx::SPR_SDR1));		

		if (!Hvx::InitializeHvHash())
			printf("Expansion installed\n");

		BYTE cpukey[0x16] = { 0 };
		QWORD cpukeyReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(cpukey);
		dump::getCPUKey(cpukey);
		cpukey[4] = 0xFF;

		//dump::DumpFuses();
		dump::DumpFuses();
		//return;

		//printf("HvxBlowFuse Test Begin\n");

		//Hvx::HvPokeDWORD(0xA560, 0x7D8802A6);
		//Hvx::HvPokeDWORD(0xA564, 0x48000299);
		//Hvx::HvPokeDWORD(0x87C8, 0x60000000);
		//Hvx::HvPokeDWORD(0xA7B8, 0x60000000); // 8674

		//Hvx::HvPokeDWORD(0x8654, 0x60000000);
		//Hvx::HvPokeDWORD(0x8674, 0x60000000);
		//Hvx::HvPokeDWORD(0x8758, 0x60000000); // 8654

		////Hvx::HvPokeDWORD(0x866C, 0x480087A2);
		//Hvx::HvPokeDWORD(0x8F74, 0x48008F9E); // 0x4800936A
		//Hvx::HvPokeDWORD(0xA630, 0x4800A7C6);
		//printf("XeBuild Patch Fixed\n");

		//QWORD hsprg1 = Hvx::HvPeekSPR(Hvx::SPR_HSPRG1);
		//printf("HSPRG1: %016llX\n", hsprg1);
		//QWORD hsprg1Data = Hvx::HvPeekBYTE(hsprg1 + 0x80);
		//printf("HSPRG1+0x80 BYTE: %02X\n", hsprg1Data);
		//Hvx::HvPokeBYTE(hsprg1 + 0x80, 0);
		//hsprg1Data = Hvx::HvPeekBYTE(hsprg1 + 0x80);
		//printf("HSPRG1+0x80 BYTE 2: %02X\n", hsprg1Data);
		//printf("HSPRG1+0x81 BYTE: %02X\n", Hvx::HvPeekBYTE(hsprg1 + 0x81));
		//printf("HSPRG1+0x82 BYTE: %02X\n", Hvx::HvPeekBYTE(hsprg1 + 0x82));

		//hsprg1 = (hsprg1 + 0x10000) - 0x5F7F;
		//Hvx::HvPokeBYTE(hsprg1, 1);
		//printf("%016llX : %02X\n", hsprg1, Hvx::HvPeekBYTE(hsprg1));
		//hsprg1 -= 0x2000;
		//Hvx::HvPokeBYTE(hsprg1, 1);
		//printf("%016llX : %02X\n", hsprg1, Hvx::HvPeekBYTE(hsprg1));
		//hsprg1 -= 0x2000;
		//Hvx::HvPokeBYTE(hsprg1, 1);
		//printf("%016llX : %02X\n", hsprg1, Hvx::HvPeekBYTE(hsprg1));
		//hsprg1 -= 0x2000;
		//Hvx::HvPokeBYTE(hsprg1, 1);
		//printf("%016llX : %02X\n", hsprg1, Hvx::HvPeekBYTE(hsprg1));
		//hsprg1 -= 0x2000;
		//Hvx::HvPokeBYTE(hsprg1, 1);
		//printf("%016llX : %02X\n", hsprg1, Hvx::HvPeekBYTE(hsprg1));

		//printf("Old update sequence: %016llX\n", Hvx::HvPeekBYTE(0x2000164D4));
		//Hvx::HvPokeBYTE(0x2000164D4, 8);
		//printf("New update sequence: %016llX\n", Hvx::HvPeekBYTE(0x2000164D4));

		////Hvx::HvPokeDWORD(0x218, 0x4E800020);

		//QWORD ret = Hvx::HvBlowFuses(0x10);
		//printf("result: %016llX\n", ret);
		//
		////Hvx::HvPokeDWORD(0x218, 0x7C7E4AA6);

		//printf("HvxBlowFuse Test End\n");

		////dump::DumpFuses();

		//return;

		QWORD zAddy[0xD] = {
			0x34000C, 			// HV 0x34-0x3F, 0xC bytes
			0x400030, 			// HV 0x40-0x6F, 0x30 bytes
			0x700004, 			// HV 0x70-0x73, 4 bytes
			0x780008, 			// HV 0x78-0x7F, 8 bytes
			0x8081FF, 			// SRAM 0x2-0x3FF, 0x3FE bytes ; HV 0x80-0xFFFF
			0x2000100C00040, 	// HV 0x100C0-0x100FF, 0x40 bytes
			0x2000103500030, 	// HV 0x10350-0x1037F, 0x30 bytes
			0x20001038080BB, 	// SRAM 0x40E-0x583, 0x176 bytes ; HV 0x10380-0x160FF
			0x2000161000040, 	// HV 0x16100-0x1613F, 0x40 bytes
			0x200016D200060, 	// HV 0x16D20-0x16D7F, 0x60 bytes
			0x200016D808125, 	// SRAM 0x5B6-0x7FF, 0x24A bytes ; HV 0x16D80-0x1FFFF
			0x4000200008200, 	// SRAM 0x800-0xBFF, 0x400 bytes ; HV 0x20000-0x2FFFF
			0x6000300008200  	// SRAM 0xC00-0xFFF, 0x400 bytes ; HV 0x30000-0x3FFFF
		};

		PQWORD pqwSocKeys = (PQWORD)XPhysicalAllocM(0x30);
		ZeroMemory(pqwSocKeys, 0x30);
		Hvx::HvPeekBytes(0x200010100, pqwSocKeys, 0x30);
		printf("Keys:\n");
		printf("WhiteningKeyHigh: %016llX\n", pqwSocKeys[0]);
		printf("WhiteningKeyLow: %016llX\n", pqwSocKeys[1]);

		// write keys are wrong, need to go through sbox stuff first
		printf("AESKeyHigh: %016llX\n", pqwSocKeys[2]);
		printf("AESKeyLow: %016llX\n", pqwSocKeys[3]);

		printf("HashKeyHigh: %016llX\n", pqwSocKeys[4]);
		printf("HashKeyLow: %016llX\n", pqwSocKeys[5]);

		QWORD pqwSocHashKey[2] = { pqwSocKeys[4], pqwSocKeys[5] };

		BYTE pbZeroEnc[0x10] = { 0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E }; // writing this to encrypted space will put zeros in memory
		QWORD pqwZeroEncBlock[0x10] = { ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1], ((PQWORD)pbZeroEnc)[0], ((PQWORD)pbZeroEnc)[1] };
		BYTE pbEncHash[0x14] = { 0 };
		QWORD pbEncHashReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(&pbEncHash);
		BYTE pbDecHash[0x14] = { 0 };
		BYTE pbZeroBlock[0x80] = { 0 };
		QWORD pbZeroBlockReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(&pbZeroBlock);
		QWORD pqwKeyTests[4] = { 0, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 0xFFFFFFFFFFFFFFFF };

		PBYTE pbSalt = (PBYTE)XPhysicalAllocM(0x80);
		QWORD pbSaltReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(pbSalt);
		ZeroMemory(pbSalt, 0x80);

		//dump::DumpHv();
		PBYTE pbHv = (PBYTE)XPhysicalAllocM(0x40000);
		QWORD pbHvReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(pbHv);
		ZeroMemory(pbHv, 0x40000);
		if (!CReadFile("Hdd:\\XeKeys\\HV_dump_17511.bin", pbHv, 0x40000))
			printf("Failed to open file\n");

		PBYTE pbHVPage0 = (PBYTE)XPhysicalAllocM(0x40000);
		memcpy(pbHVPage0, (PVOID)0x80000000, 0x40000);
		CWriteFile("hdd:\\XeKeys\\HV0_enc.bin", pbHVPage0, 0x40000);

		// set up the protected buffer
		PBYTE pbBuf = (PBYTE)XPhysicalAlloc(0x80, MAXULONG_PTR, 0x10000, PAGE_READWRITE);
		ZeroMemory(pbBuf, 0x80);
		DWORD pbBufPhys = (DWORD)MmGetPhysicalAddress(pbBuf);
		QWORD pbBufReal = 0x8000000000000000ULL | pbBufPhys;
		QWORD pbBufProt = Hvx::HvProc(Hvx::HvpRelocatePhysicalToProtected, 3, pbBufPhys, 0x80, 0x3E);

		QWORD pqwCRCTest[3][16] =
		{
			{
				0x141560da0ab1bcad,
				0x963bba5813e57bff,
				0x18625591cfcd16e5,
				0x70a0c479fdce721a,
				0x7417ab53592e6960,
				0xed29e65a0e36c3a1,
				0x2a443f75788848a2,
				0x2028aed370a321ee,
				0x24e6e4912b55e3eb,
				0xcf0aa31219b6046a,
				0xf6d44bfb71329456,
				0xc2f89d21b462e8a5,
				0x6eecbdb94d622608,
				0xe0818f074d685c9c,
				0xdb873d00da4a38ee,
				0x1874355fb9226979
			},
			{
				0x6f7b2357ee6be91c,
				0xfd5da6a8251a95ba,
				0x89716cc8ad4fd1b5,
				0x4b7f3e107119f59a,
				0x71f2c09e772700ce,
				0x8623833406fedd5c,
				0xf573468ea25cce3e,
				0x997c6578eefb2cb3,
				0x58a078fb4e319d7a,
				0x86fccdac4f720aa6,
				0x52a1bb981d86284f,
				0x0fbc70b6747f278d,
				0x2bde2bc1e4572afe,
				0x13ad5b85f6a2fc03,
				0xf38da469fd3a095b,
				0x294c3c4833b8b9e8
			},
			{
				pqwCRCTest[0][0] ^ pqwCRCTest[1][0],
				pqwCRCTest[0][1] ^ pqwCRCTest[1][1],
				pqwCRCTest[0][2] ^ pqwCRCTest[1][2],
				pqwCRCTest[0][3] ^ pqwCRCTest[1][3],
				pqwCRCTest[0][4] ^ pqwCRCTest[1][4],
				pqwCRCTest[0][5] ^ pqwCRCTest[1][5],
				pqwCRCTest[0][6] ^ pqwCRCTest[1][6],
				pqwCRCTest[0][7] ^ pqwCRCTest[1][7],
				pqwCRCTest[0][8] ^ pqwCRCTest[1][8],
				pqwCRCTest[0][9] ^ pqwCRCTest[1][9],
				pqwCRCTest[0][10] ^ pqwCRCTest[1][10],
				pqwCRCTest[0][11] ^ pqwCRCTest[1][11],
				pqwCRCTest[0][12] ^ pqwCRCTest[1][12],
				pqwCRCTest[0][13] ^ pqwCRCTest[1][13],
				pqwCRCTest[0][14] ^ pqwCRCTest[1][14],
				pqwCRCTest[0][15] ^ pqwCRCTest[1][15]
		}
		};

		QWORD pqwCRCTest2[16] =
		{
			0x6f7b2357ee6be91c,
			0xfd5da6a8251a95ba,
			0x89716cc8ad4fd1b5,
			0x4b7f3e107119f59a,
			0x71f2c09e772700ce,
			0x8623833406fedd5c,
			0xf573468ea25cce3e,
			0x997c6578eefb2cb3,
			0x58a078fb4e319d7a,
			0x86fccdac4f720aa6,
			0x52a1bb981d86284f,
			0x0fbc70b6747f278d,
			0x2bde2bc1e4572afe,
			0x13ad5b85f6a2fc03,
			0xf38da469fd3a095b,
			0x294c3c4833b8b9e8
		};

		QWORD pqwBitPattern[4] =
		{
			0,
			0xB2B2B2B2B2B2B2B2,
			0x7676767676767676,
			0xC4C4C4C4C4C4C4C4
		};

		for (int j = 0; j < 23; j++)
		{
			
			ZeroMemory(pbSalt, 0x80);
			ZeroMemory(pbEncHash, 0x14);

			if (j < 4)
			{
				continue;
				for (int i = 0; i < 0x10; i += 2)
				{
					((PQWORD)pbSalt)[i] = pqwKeyTests[j];
					((PQWORD)pbSalt)[i + 1] = pqwKeyTests[j];
				}
			}
			
			else if(j < 20)
			{
				continue;
				DWORD dwShift = (j-4);
				//printf("\nShift: %d\n", dwShift);
				((PQWORD)pbSalt)[0] = 0;// x0000000000000011;
				((PQWORD)pbSalt)[1] = 0;// x0000000000000013;
				((PQWORD)pbSalt)[2] = 0;// x0000000000000011;
				((PQWORD)pbSalt)[3] = 0;// x0000000000000011;
				((PQWORD)pbSalt)[4] = 0;// x0000000000000002;
				((PQWORD)pbSalt)[5] = 0;// x0000000000000001;
				((PQWORD)pbSalt)[6] = 0;// x0000000000000001;
				((PQWORD)pbSalt)[7] = 0;// x0000000000000002;
				((PQWORD)pbSalt)[8] = 0;// x0000000000000000;
				((PQWORD)pbSalt)[9] = 0;// x0000000000000001;
				((PQWORD)pbSalt)[10] = 0;// x0000000000000003;
				((PQWORD)pbSalt)[11] = 0;// x0000000000000001;
				((PQWORD)pbSalt)[12] = 0;// xFFFFFFFFFFFFFFFE;
				((PQWORD)pbSalt)[13] = 0;// xFFFFFFFFFFFFFFFE;
				((PQWORD)pbSalt)[14] = 0;// xFFFFFFFFFFFFFFFF;
				((PQWORD)pbSalt)[15] = 0x1 << dwShift;// xFFF8;
				/*for (int i = 0; i < 0x10; i += 2)
				{
					((PQWORD)pbSalt)[i] = pqwSocHashKey[0];
					((PQWORD)pbSalt)[i + 1] = pqwSocHashKey[1];
				}*/
			}

			else
			{
				WORD pwTestHashes[3] = { 0 };
				for (int l = 0; l < 3; l++)
				{
					printf("\nTest %d\n", l + 1);
					for (int k = 0; k < 4; k++)
					{
						for (int i = 0; i < 16; i++)
							((PQWORD)pbSalt)[i] = pqwCRCTest[l][i] ^ pqwBitPattern[k];

						printf("\nBlock of\n");
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[0], ((PQWORD)pbSalt)[1]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[2], ((PQWORD)pbSalt)[3]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[4], ((PQWORD)pbSalt)[5]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[6], ((PQWORD)pbSalt)[7]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[8], ((PQWORD)pbSalt)[9]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[10], ((PQWORD)pbSalt)[11]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[12], ((PQWORD)pbSalt)[13]);
						printf("%016llX %016llX\n", ((PQWORD)pbSalt)[14], ((PQWORD)pbSalt)[15]);

						printf("My Algo (no key): %04X\n", SoCHash(pbSalt));
						Hvx::HvHash(0x8001ull, pbBufProt, pbSaltReal, pbEncHashReal);
						WORD wHash = ((PWORD)pbEncHash)[0];
						printf("SOC (keys used): %04X\n", wHash);
						printf("Bit Pattern: %016llX\n", pqwBitPattern[k]);

						if(k == 0)
							pwTestHashes[l] = wHash;
						else
							printf("Difference (%04X XOR %04X): %04X\n", wHash, pwTestHashes[l], wHash ^ pwTestHashes[l]);

						printf("Test Key: %04X\n", SoCHashTest(pbSalt, pqwSocHashKey));

						//break;
						Sleep(150);
					}
				}

				printf("\nTest 1 Hash: %04X\n", pwTestHashes[0]);
				printf("Test 2 Hash: %04X\n", pwTestHashes[1]);
				printf("Test 3 Hash: %04X\n", pwTestHashes[2]);
				printf("\nTest 1 Hash XOR Test 2 Hash: %04X\n", pwTestHashes[0] ^ pwTestHashes[1]);
				break;
			}

			printf("\nBlock of\n");
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[0], ((PQWORD)pbSalt)[1]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[2], ((PQWORD)pbSalt)[3]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[4], ((PQWORD)pbSalt)[5]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[6], ((PQWORD)pbSalt)[7]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[8], ((PQWORD)pbSalt)[9]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[10], ((PQWORD)pbSalt)[11]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[12], ((PQWORD)pbSalt)[13]);
			printf("%016llX %016llX\n", ((PQWORD)pbSalt)[14], ((PQWORD)pbSalt)[15]);

			printf("Without Key: %04X\n", SoCHash((pbSalt)));
			Hvx::HvHash(0x8001ull, pbBufProt, pbSaltReal, pbEncHashReal);
			printf("With Key: %04X\n", ((PWORD)pbEncHash)[0]);
			printf("Test Key: %04X\n", SoCHashTest(pbSalt, pqwSocHashKey));
			//break;
			Sleep(150);
		}

		printf("\n");

		/*
		printf("Block of HV+0x80: %04X\n", SoCHash(pbHv + 0x80));
		printf("Block of HV+0x10380: %04X\n", SoCHash(pbHv + 0x10380));
		printf("Block of HV+0x16D80: %04X\n", SoCHash(pbHv + 0x16D80));
		printf("Block of HV+0x20000: %04X\n", SoCHash(pbHv + 0x20000));
		printf("Block of HV+0x30000: %04X\n", SoCHash(pbHv + 0x30000));
		*/

		printf("Key Test:\n");
		printf("Block of HV+0x80: %04X\n", SoCHashTest(pbHv + 0x80, pqwSocHashKey));
		printf("Block of HV+0x10380: %04X\n", SoCHashTest(pbHv + 0x10380, pqwSocHashKey));
		printf("Block of HV+0x16D80: %04X\n", SoCHashTest(pbHv + 0x16D80, pqwSocHashKey));
		printf("Block of HV+0x20000: %04X\n", SoCHashTest(pbHv + 0x20000, pqwSocHashKey));
		printf("Block of HV+0x30000: %04X\n", SoCHashTest(pbHv + 0x30000, pqwSocHashKey));

		for (int i = 0; i < 0xD; i++)
		{
			QWORD xAddy = zAddy[i];
			if (xAddy & 0x8000)
			{
				//printf("\nxAddy: %016llX\n", xAddy);
				//printf("\nHvBuf: %016llX\n", pbHvReal);
				PBYTE pbBufHash = (PBYTE)XPhysicalAllocM((xAddy & 0x3FF) << 1);
				ZeroMemory(pbBufHash, (xAddy & 0x3FF) << 1);
				QWORD pbBufHashReal = 0x8000000000000000ULL | (DWORD)MmGetPhysicalAddress(pbBufHash);

				//printf("BufHashReal: %016llX\n", pbBufHashReal);

				QWORD ret = Hvx::HvHash(xAddy, pbBufProt, pbHvReal, pbBufHashReal);

				printf("Block at HV+%X, With Key: %04X\n", (xAddy >> 16) & 0x3FFFF, Hvx::HvPeekWORD(ProtToSRAM(xAddy >> 16)));
				printf("Block at HV+%X, Without Key: %04X\n", (xAddy >> 16) & 0x3FFFF, SoCHash((pbHv+((xAddy >> 16) & 0x3FFFF))));
				printf("Block at HV+%X, Without Key: %04X\n", (xAddy >> 16) & 0x3FFFF, SoCHashBy16A((pbHv + ((xAddy >> 16) & 0x3FFFF))));
				//printf("Hash Buffer: ");
				//arrPrintXln(pbBufHash, 0x10);

				XPhysicalFree(pbBufHash);
			}
		}

		Hvx::HvProc(Hvx::HvpInvalidateCachelines, 2, pbBufProt, 0x80);
		Hvx::HvProc(Hvx::HvpZeroCacheLines, 2, pbBufReal, 1);

		XPhysicalFree(pbBuf);

		printf("Done!\n");
	}

	void DumpCacheExp()
	{
		dump::DumpCache();
		return;
	}

	void XNotifyTime()
	{
		XNotify(getTime());
	}

	void DumpHvExp()
	{
		dump::DumpHv();
		return;
	}

	void Dump2blArea()
	{
		BYTE CPUKey[0x10] = { 0 };
		dump::getCPUKey(CPUKey);
		printf("CPUKEY: 0x");
		for (int i = 0; i < 0x10; i++)
			printf("%X", CPUKey[i]);
		printf("\n");
		dump::DumpCB_A();
		dump::DumpCB_B();
	}

	void DumpChalData()
	{
		dump::DumpData("usb:\\XeKeys\\ChalData.bin");
	}

	void ExecuteFile(DWORD rSize)
	{

		DWORD Size = 0x1000;
		DWORD RetBufSize = rSize;
		PBYTE bpayload = (PBYTE)XPhysicalAlloc(Size, MAXULONG_PTR, NULL, PAGE_READWRITE);
		PBYTE bRetBuf = (PBYTE)XPhysicalAlloc(RetBufSize, MAXULONG_PTR, NULL, PAGE_READWRITE);
		memset(bpayload, 0, Size);
		memset(bRetBuf, 0, RetBufSize);

		QWORD physRetBuf = 0x8000000000000000ULL + (DWORD)MmGetPhysicalAddress(bRetBuf);
		if (!CReadFile("hdd:\\XeKeys\\KeysExecutePayload.bin", bpayload, Size))
		{
			printf("Couldn't open payload file\n");
			return;
		}
		printf("Return buffer: 0x%X\n", RetBufSize);

		QWORD pqwSave[8] = { 0 };
		QWORD pqwSaveReal = 0x8000000000000000ULL + (DWORD)MmGetPhysicalAddress(pqwSave);
		QWORD DbgRet = Hvx::ExecutePayload(bpayload, Size, 0, pqwSaveReal, NULL, NULL, NULL);

		printf("Save Buffer:\n");
		printf("%016llX\n", pqwSave[0]);
		printf("%016llX\n", pqwSave[1]);
		printf("%016llX\n", pqwSave[2]);
		printf("%016llX\n", pqwSave[3]);
		printf("%016llX\n", pqwSave[4]);
		printf("%016llX\n", pqwSave[5]);
		printf("%016llX\n", pqwSave[6]);
		printf("%016llX\n", pqwSave[7]);

		printf("VID: %016llX\n", Hvx::HvPeekQWORD(__REG_61188));

		if (!CWriteFile("hdd:\\XeKeys\\bRetBuf.bin", bRetBuf, RetBufSize))
			return;

		XPhysicalFree(bpayload);
		XPhysicalFree(bRetBuf);

		printf("Execute Done\n");
	}

	void DumpFuse()
	{
		printf("Dumping fuses...\n");
		dump::DumpFuses();
		printf("Done\n");
	}
}