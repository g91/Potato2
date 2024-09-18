#include "stdafx.h"

namespace Challenge {

	DWORD XamLoaderExecuteAsyncChallengeHook(DWORD Address, DWORD Task, PBYTE TableName, DWORD TableSize, PBYTE Buffer, DWORD BufferSize);
	DWORD XeKeysExecuteHook(PBYTE Buffer, DWORD Size, PBYTE Salt, PXBOX_KRNL_VERSION KrnlBuild, PDWORD r7, PDWORD r8);
	VOID sub_23918(BYTE* Sig, BYTE* Key, BYTE* XeRand);
	VOID sub_23830(BYTE* in_1, DWORD size_1, BYTE* in_2, DWORD size_2);
	VOID DumpFiles(PBYTE Salt, PBYTE Buffer, PBYTE Hashes);
	VOID DumpFilesLoop(PBYTE Salt, PBYTE Buffer);
	//VOID DumpSOC();
	VOID RestartMe();
	extern BYTE Salts[256][16];
	extern BYTE ChalKey[144];
}