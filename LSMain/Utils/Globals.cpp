#include "stdafx.h"
namespace Globals {

	//now to the global variables
	BYTE Spoofed_CPUKey[16];
	BYTE Real_CPUKey[16];
	BYTE Genealogy[16];
	KV_Structure::KEY_VAULT KeyVault;
	HANDLE hModule;
	BOOL Initialized = FALSE;
	BOOL DashLoaded = FALSE;
	BOOL IsDevkit = FALSE;
	BOOL FCRT = FALSE;
	BOOL Type1KV = FALSE;
	BOOL CRL = FALSE;
	XEX_EXECUTION_ID SpoofedExecutionId;
	BYTE MacAddress[6];
	DWORD UpdateSequence = 29;

	BYTE KVDigest[XECRYPT_SHA_DIGEST_SIZE];
	BYTE Dumped_HV[0x40000];

	BYTE XOSCBuffer[0x400];
	BYTE IPXOSCBuffer[0x404];
	BYTE XKEBuffer[0x100]; 
	BYTE IPXKEBuffer[0x128]; 
	BOOL DumpXKE = FALSE;
	BOOL DumpXOSC = FALSE;
}