#include "stdafx.h"

#pragma warning(push)
#pragma warning(disable:4826) // Get rid of the sign-extended warning

namespace Utilities {

	pDmSetMemory DevSetMemory = NULL;
	BOOL dbgInit = FALSE;
	CRITICAL_SECTION dbgLock;

#ifdef _DEBUG

	VOID PrintToLog(const CHAR* strFormat, ...) {

		if(dbgInit == FALSE) {
			InitializeCriticalSection(&dbgLock);
			dbgInit = TRUE;
		}	

		CHAR buffer[1000];

		va_list pArgList;
		va_start( pArgList, strFormat );
		vsprintf_s( buffer, 1000, strFormat, pArgList );
		va_end(pArgList);

		printf("[XeNoN] %s %s", buffer, "\r\n");

		EnterCriticalSection(&dbgLock);
		std::ofstream writeLog;
		writeLog.open(PATH_LOG, std::ofstream::app);
		if (writeLog.is_open()){
			writeLog.write(buffer, strlen(buffer));
			writeLog.write("\r\n", 1);
		}
		writeLog.close();
		LeaveCriticalSection(&dbgLock);
	}

#endif

	CONST CHAR* FormatBytes(PBYTE bytes, DWORD len) {
		std::string buffer;
		if (!bytes || !len) return "";
		for (int i = 0; i<(int)len; i++) {
			char tmp[2];
			sprintf(tmp, "%02X", bytes[i]);
			buffer.append(tmp);
		}
		return buffer.c_str();
	}

	INT toWCHAR(PCHAR input, PWCHAR output) {
		if (!input || !output) return 0;
		INT len = strlen(input);

		memset(output, 0, (len * 2) + 2);
		for (INT i = 1, b = 0; b<len; i += 2) {
			((CHAR*)output)[i] = input[b];
			b++;
		}
		return len;
	}


	VOID ThreadMe(LPTHREAD_START_ROUTINE lpStartAddress) {
		HANDLE handle;
		DWORD lpThreadId;
		ExCreateThread(&handle, 0, &lpThreadId, (PVOID)XapiThreadStartup, lpStartAddress, NULL, 0x2 | CREATE_SUSPENDED);
		XSetThreadProcessor(handle, 4);
		SetThreadPriority(handle, THREAD_PRIORITY_ABOVE_NORMAL);
		ResumeThread(handle);
	}

	BOOL XeKeysPkcs1Verify(CONST PBYTE pbHash, CONST PBYTE pbSig, XECRYPT_RSA* pRsa) {
		byte scratch[0x100];
		DWORD val = pRsa->cqw << 3;
		if (val <= 0x200) {
			XeCryptBnQw_SwapDwQwLeBe((PQWORD)pbSig, (PQWORD)scratch, val >> 3);
			if (XeCryptBnQwNeRsaPubCrypt((PQWORD)scratch, (PQWORD)scratch, pRsa) == 0) return FALSE;
			XeCryptBnQw_SwapDwQwLeBe((PQWORD)scratch, (PQWORD)scratch, val >> 3);
			return XeCryptBnDwLePkcs1Verify((CONST PBYTE)pbHash, scratch, val);
		} else return FALSE;
	}

	VOID __declspec(naked) GLPR(VOID) {
		__asm {
			std     r14, -0x98(sp)
				std     r15, -0x90(sp)
				std     r16, -0x88(sp)
				std     r17, -0x80(sp)
				std     r18, -0x78(sp)
				std     r19, -0x70(sp)
				std     r20, -0x68(sp)
				std     r21, -0x60(sp)
				std     r22, -0x58(sp)
				std     r23, -0x50(sp)
				std     r24, -0x48(sp)
				std     r25, -0x40(sp)
				std     r26, -0x38(sp)
				std     r27, -0x30(sp)
				std     r28, -0x28(sp)
				std     r29, -0x20(sp)
				std     r30, -0x18(sp)
				std     r31, -0x10(sp)
				stw     r12, -0x8(sp)
				blr
		}
	}

	DWORD RelinkGPLR(DWORD SFSOffset, PDWORD SaveStubAddress, PDWORD OriginalAddress) {
		DWORD Instruction = 0, Replacing;
		PDWORD Saver = (PDWORD)GLPR;
		if (SFSOffset & 0x2000000) {
			SFSOffset = SFSOffset | 0xFC000000;
		}

		Replacing = OriginalAddress[SFSOffset / 4];
		for (int i = 0; i < 20; i++) {
			if (Replacing == Saver[i]) {
				DWORD NewOffset = (DWORD)&Saver[i] - (DWORD)SaveStubAddress;
				Instruction = 0x48000001 | (NewOffset & 0x3FFFFFC);
			}
		}
		return Instruction;
	}

	DWORD ApplyPatches(PVOID buffer) {
		DWORD PatchCount = NULL;
		PDWORD PatchData = (PDWORD)buffer;
		while (*PatchData != 0xFFFFFFFF) {
			memcpy((PVOID)PatchData[0], &PatchData[2], PatchData[1] * sizeof(DWORD));
			PatchData += (PatchData[1] + 2);
			PatchCount++;
		}
		return PatchCount;
	}




	VOID HookFunctionStart(PDWORD Address, PDWORD SaveStub, DWORD Destination) {
		if ((SaveStub != NULL) && (Address != NULL)) {
			DWORD AddressRelocation = (DWORD)(&Address[4]);
			if (AddressRelocation & 0x8000)
				SaveStub[0x00] = 0x3D600000 + (((AddressRelocation >> 0x10) & 0xFFFF) + 0x01);
			else
				SaveStub[0x00] = 0x3D600000 + ((AddressRelocation >> 0x10) & 0xFFFF);
			SaveStub[0x01] = 0x396B0000 + (AddressRelocation & 0xFFFF);
			SaveStub[0x02] = 0x7D6903A6;
			for (INT i = 0; i < 0x04; i++) {
				if ((Address[i] & 0x48000003) == 0x48000001)
					SaveStub[i + 0x03] = RelinkGPLR((Address[i] & ~0x48000003), &SaveStub[i + 0x03], &Address[i]);
				else
					SaveStub[i + 0x03] = Address[i];
			}
			SaveStub[0x07] = 0x4E800420;
			__dcbst(0x00, SaveStub);
			__sync();
			__isync();
			PatchInJump(Address, Destination, FALSE);
		}
	}

	VOID PatchInJump(DWORD* Address, DWORD Destination, BOOL Linked) {
		Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
		if (Destination & 0x8000) Address[0] += 1;
		Address[1] = 0x396B0000 + (Destination & 0xFFFF);
		Address[2] = 0x7D6903A6;
		Address[3] = Linked ? 0x4E800421 : 0x4E800420;
	}

	VOID PatchInBranch(DWORD* Address, DWORD Destination, BOOL Linked) {
		Address[0] = (0x48000000 + ((Destination - (DWORD)Address) & 0x3FFFFFF));
		if (Linked) Address[0] += 1;
	}

	FARPROC ResolveFunction(PCHAR ModuleName, DWORD Ordinal) {
		HMODULE mHandle = GetModuleHandle(ModuleName);
		return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
	}

	DWORD PatchModuleImport(PCHAR Module, PCHAR ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
		LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(Module);
		return (moduleHandle == NULL) ? S_FALSE : PatchModuleImport(moduleHandle, ImportedModuleName, Ordinal, PatchAddress);
	}

	DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, PCHAR ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
		DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
		if (address == NULL) return S_FALSE;

		VOID* headerBase = Module->XexHeaderBase;
		PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
		if (importDesc == NULL) return S_FALSE;

		DWORD result = 2;
		PCHAR stringTable = (PCHAR)(importDesc + 1);
		XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);
		for (DWORD x = 0; x < importDesc->ModuleCount; x++) {
			DWORD* importAdd = (DWORD*)(importTable + 1);
			for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {
				DWORD value = *((DWORD*)importAdd[y]);
				if (value == address) {
					SetMemory((DWORD*)importAdd[y], &PatchAddress, 4);
					DWORD newCode[4];
					PatchInJump(newCode, PatchAddress, FALSE);
					SetMemory((DWORD*)importAdd[y + 1], newCode, 16);
					result = S_OK;
				}
			}

			importTable = (XEX_IMPORT_TABLE_ORG*)(((PBYTE)importTable) + importTable->TableSize);
		}
		return result;
	}

	HRESULT CreateSymbolicLink(PCHAR szDrive, PCHAR szDeviceName, BOOL System) {
		CHAR szDestinationDrive[MAX_PATH];
		sprintf_s(szDestinationDrive, MAX_PATH, System ? "\\System??\\%s" : "\\??\\%s", szDrive);

		ANSI_STRING linkname, devicename;
		RtlInitAnsiString(&linkname, szDestinationDrive);
		RtlInitAnsiString(&devicename, szDeviceName);
		if (FileExists(szDrive)) return S_OK;
		NTSTATUS status = ObCreateSymbolicLink(&linkname, &devicename);
		return (status >= 0) ? S_OK : S_FALSE;
	}

	HRESULT DeleteSymbolicLink(PCHAR szDrive, BOOL System) {
		CHAR szDestinationDrive[MAX_PATH];
		sprintf_s(szDestinationDrive, MAX_PATH, System ? "\\System??\\%s" : "\\??\\%s", szDrive);
		ANSI_STRING linkname;
		RtlInitAnsiString(&linkname, szDestinationDrive);
		NTSTATUS status = ObDeleteSymbolicLink(&linkname);
		return (status >= 0) ? S_OK : S_FALSE;
	}

	BOOL CReadFile(CONST PCHAR FileName, MemoryBuffer &pBuffer) {
		HANDLE hFile; DWORD dwFileSize, dwNumberOfBytesRead;
		hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		dwFileSize = GetFileSize(hFile, NULL);
		PBYTE lpBuffer = (PBYTE)malloc(dwFileSize);
		if (lpBuffer == NULL) {
			CloseHandle(hFile);
			return FALSE;
		}

		if (ReadFile(hFile, lpBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) == FALSE) {
			free(lpBuffer);
			CloseHandle(hFile);
			return FALSE;
		} else if (dwNumberOfBytesRead != dwFileSize) {
			free(lpBuffer);
			CloseHandle(hFile);
			return FALSE;
		}

		CloseHandle(hFile);
		pBuffer.Add(lpBuffer, dwFileSize);
		free(lpBuffer);
		return TRUE;
	}

	BOOL CWriteFile(CONST PCHAR FilePath, CONST PVOID Data, DWORD Size) {
		HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fHandle == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		DWORD writeSize = Size;
		if (WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE) {
			return FALSE;
		}
		CloseHandle(fHandle);
		return TRUE;
	}

	BOOL FileExists(LPCSTR lpFileName) {
		if (GetFileAttributes(lpFileName) == -1) {
			DWORD lastError = GetLastError();
			if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
				return FALSE;
		}
		return TRUE;
	}

	BOOL IsTrayOpen() {
		byte msg[0x10];
		byte resp[0x10];
		memset(msg, 0x0, 0x10);
		msg[0] = 0xa;
		HalSendSMCMessage(msg, resp);

		if (resp[1] == 0x60) return TRUE;
		else return FALSE;
	}

	BOOL pfShow = (BOOL)0xDEADBEEF;
	BOOL pfShowMovie;
	BOOL pfPlaySound;
	BOOL pfShowIPTV;

	VOID ToggleNotify(BOOL Status) {
		if ((INT)pfShow == 0xDEADBEEF) XNotifyUIGetOptions(&pfShow, &pfShowMovie, &pfPlaySound, &pfShowIPTV);
		if (!Status) XNotifyUISetOptions(pfShow, pfShowMovie, pfPlaySound, pfShowIPTV);
		else XNotifyUISetOptions(TRUE, TRUE, TRUE, TRUE);
		Sleep(500);
	}

	VOID XNotifyDoQueueUI(PWCHAR pwszStringParam) {
		ToggleNotify(TRUE);
		XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, pwszStringParam, NULL);
		ToggleNotify(FALSE);
	}

	VOID XNotifyUI(PWCHAR pwszStringParam) {
		if (KeGetCurrentProcessType() != PROC_USER) {
			HANDLE th = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)XNotifyDoQueueUI, (LPVOID)pwszStringParam, CREATE_SUSPENDED, NULL);
			if (th == NULL) return;
			ResumeThread(th);
		} else {
			XNotifyDoQueueUI(pwszStringParam);
		}
	}

	BOOL GetSectionInfo(CONST PCHAR SectionName, PDWORD Address, PDWORD Length) {
		DWORD SectionInfoOffset = 0x82000000;
		while (!strcmp(".rdata", (PCHAR)SectionInfoOffset) == FALSE) SectionInfoOffset += 4;
		PIMAGE_SECTION_HEADER DefaultSections = (PIMAGE_SECTION_HEADER)SectionInfoOffset;

		BOOL Succeded = FALSE;
		for (DWORD i = 0; strlen((PCHAR)DefaultSections[i].Name); i++) {
			if (!strcmp(SectionName, (PCHAR)DefaultSections[i].Name) == TRUE) {
				*Address = 0x82000000 + _byteswap_ulong(DefaultSections[i].VirtualAddress);
				*Length = _byteswap_ulong(DefaultSections[i].Misc.VirtualSize);
				Succeded = TRUE;
				break;
			}
		}
		return Succeded;
	}

	BOOL DataCompare(PBYTE pbData, PBYTE pbMask, PCHAR szMask) {
		for (; *szMask; ++szMask, ++pbData, ++pbMask) {
			if (*szMask == 'X' && *pbData != *pbMask) {
				return FALSE;
			}
		}
		return (*szMask == NULL);
	}

	DWORD FindPattern(PCHAR SectionName, PCHAR pbMask, PCHAR szMask, CHAR label[50]) {
		BOOL dump = TRUE;
		DWORD Address, Length;
		if (GetSectionInfo(SectionName, &Address, &Length) == TRUE) {
			for (DWORD i = 0; i < Length; i++) {
				if (DataCompare((PBYTE)(Address + i), (PBYTE)pbMask, szMask) == TRUE) {
					#ifdef _DUMPOffets
					if (label != NULL) DbgPrint("Addr %s = 0x%08X", label, Address + i);
					#endif
					return Address + i;
				}
			}
		}
		#ifdef _DUMPOffets
		if (label != NULL) DbgPrint("Addr %s FAILLED", label);
		#endif
		return NULL;
	}

	DWORD ReadHighLow(DWORD Address, DWORD HighAdditive, DWORD LowAdditive, CHAR label[50]) {
		DWORD returnAddr = (*(PWORD)(Address + HighAdditive) << 16) | *(PWORD)(Address + LowAdditive);
		DWORD returnFinal = (returnAddr & 0x8000) ? returnAddr - 0x10000 : returnAddr;
		#ifdef _DUMPOffets
		if (label != NULL) DbgPrint("Addr %s = 0x%08X", label, returnFinal);
		#endif
		return returnFinal;
	}

	HRESULT SetMemory(PVOID Destination, PVOID Source, DWORD Length) {
		if (DevSetMemory == NULL)
			DevSetMemory = (pDmSetMemory)ResolveFunction("xbdm.xex", 40);

		if (DevSetMemory == NULL) {
			memcpy(Destination, Source, Length);
			return ERROR_SUCCESS;
		} else {
			if (DevSetMemory(Destination, Length, Source, NULL) == MAKE_HRESULT(0x00, 0x2DA, 0x00))
				return ERROR_SUCCESS;
		}
		return E_FAIL;
	}

	DWORD MakeBranch(DWORD Address, DWORD Destination, BOOL Linked) {
		return (0x48000000) | ((Destination - Address) & 0x03FFFFFF) | (DWORD)Linked;
	}

	HANDLE SearchForHandle(CONST PCHAR Module) {
		PLDR_DATA_TABLE_ENTRY Table = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle("xboxkrnl.exe");
		PXEX_HEADER_STRING String;

		Table = (PLDR_DATA_TABLE_ENTRY)Table->InLoadOrderLinks.Flink;
		while (Table != 0) {
			String = (PXEX_HEADER_STRING)RtlImageXexHeaderField(Table->XexHeaderBase, 0x000183FF);
			if ((String != 0) && (String->Data[0x00] != 0)) {
				if (stricmp((PCHAR)String->Data, Module) == 0) {
					HANDLE Return = (HANDLE)Table;
					return Return;
				}
			}
			Table = (PLDR_DATA_TABLE_ENTRY)Table->InLoadOrderLinks.Flink;
		}
		return INVALID_HANDLE_VALUE;
	}

	CHAR Buffer[0x1000];
	PCHAR LinkChar(CONST PCHAR Text, ...) {
		va_list pArgList;
		va_start(pArgList, Text);
		vsprintf(Buffer, Text, pArgList);
		va_end(pArgList);
		return Buffer;
	}

	INT RandomInRange(INT min, INT max) {
		INT n = max - min + 1;
		INT remainder = RAND_MAX % n;
		INT x;
		do { x = rand(); } while (x >= RAND_MAX - remainder);
		return min + x % n;
	}

	BOOL IsNumberBetween(INT Max, INT Min, INT Num) {
		if (Num < Max && !(Num <= Min))
			return TRUE;

		if (Num > Max && !(Num >= Min))
			return TRUE;

		return FALSE;
	}

	INT Getdec(CHAR Hex) {
		if ((Hex >= '0') && (Hex <= '9')) return Hex - '0';
		if ((Hex >= 'A') && (Hex <= 'F')) return Hex - 'A' + 10;
		if ((Hex >= 'a') && (Hex <= 'f')) return Hex - 'a' + 10;

		return -1; 
	}

	__int64 StringToU64(CONST CHAR *sz) {
		__int64 u64Result = 0;
		while (*sz != '\0') {
			u64Result *= 10;
			u64Result += *sz - '0';
			sz++;
		}
		return u64Result;
	}

	HRESULT ProcessCPUKeyBin(CHAR* FilePath) {
		MemoryBuffer mbCpu;
		if(!CReadFile(FilePath, mbCpu)) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Warn: CPUKey.bin Not Found. Creating.");
			#endif
			return Utilities::CreateCPUKeyBin(FilePath);
		} 

		if(mbCpu.GetDataLength() < 0x10 ) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Warn: CPUKey.bin is too small. Recreating.");
			#endif
			return Utilities::CreateCPUKeyBin(FilePath);
		}

		if(mbCpu.GetDataLength() > 0x10){
			#ifdef _DEBUG
			Utilities::PrintToLog("Warn: CPUKey.bin is too big. Only using 16 bytes.");
			#endif
		}

		memcpy(Globals::Spoofed_CPUKey, mbCpu.GetData(), 0x10);
		return ERROR_SUCCESS;
	}

	HRESULT CreateCPUKeyBin(CHAR* FilePath){
		XeCryptRandom(Globals::Spoofed_CPUKey, 0x10);
		if(CWriteFile(FilePath, Globals::Spoofed_CPUKey, 0x10) != TRUE){
			#ifdef _DEBUG
			Utilities::PrintToLog("ERROR: Could not write CPUKey.bin");
			#endif
			return E_FAIL;
		}
		return ERROR_SUCCESS;
	}

	HRESULT SetMacAddress() {
		Globals::MacAddress[0] = 0x00;
		Globals::MacAddress[1] = 0x22;
		Globals::MacAddress[2] = 0x48;
		Globals::MacAddress[3] = Globals::KeyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex3;
		Globals::MacAddress[4] = Globals::KeyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex4;
		Globals::MacAddress[5] = Globals::KeyVault.ConsoleCertificate.ConsoleId.asBits.MacIndex5;

		BYTE curMacAddress[6]; 
		WORD settingSize = 6;
		ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, curMacAddress, 6, &settingSize);
		if(memcmp(curMacAddress, Globals::MacAddress, 6) == 0) {
			DWORD temp = 0;
			XeCryptSha(Globals::MacAddress, 6, NULL, NULL, NULL, NULL, (BYTE*)&temp, 4);
			Globals::UpdateSequence |= (temp & ~0xFF);
			return ERROR_SUCCESS;
		}

		if(NT_SUCCESS(ExSetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, Globals::MacAddress, 6))) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Rebooting to Finalize Mac Address Change.");
			#endif
			Sleep(3000);
			HalReturnToFirmware(HalFatalErrorRebootRoutine);
		}

		return E_FAIL;
	}

	HRESULT ProcessCPUKeyFuse() {
		BYTE hvCpuCached[0x10];
		HVPeekPoke::HvPeekBytes(0x20, hvCpuCached, 0x10);
		*(PQWORD)Globals::Real_CPUKey = HVPeekPoke::HvGetFuseLine(3) | HVPeekPoke::HvGetFuseLine(4);
		*(PQWORD)(Globals::Real_CPUKey + 0x8) = HVPeekPoke::HvGetFuseLine(5) | HVPeekPoke::HvGetFuseLine(6);
		if (memcmp(Globals::Real_CPUKey, hvCpuCached, 0x10) != 0){
			return E_FAIL;
		}
		PXECRYPT_AES_STATE Key = (PXECRYPT_AES_STATE)XPhysicalAlloc(0x160, MAXULONG_PTR, 0, PAGE_READWRITE);
		XeCryptAesKey(Key, Globals::Real_CPUKey);
		BYTE Buffer[0x10];
		*(PQWORD)Buffer = HVPeekPoke::HvGetFuseLine(1);
		*(PQWORD)(Buffer + 0x8) = HVPeekPoke::HvGetFuseLine(2);
		XeCryptAesEcb(Key, Buffer, Globals::Genealogy, TRUE);
		XPhysicalFree(Key);
		//Utilities::CWriteFile("XeNoN:\\Genealogy.bin", Globals::Genealogy, 0x10);
		//Utilities::CWriteFile("XeNoN:\\Real_CPUKey.bin", Globals::Real_CPUKey, 0x10);
		return ERROR_SUCCESS;
	}

	HRESULT CreateIni(){
		/*VOID* buffer;
		DWORD size;
		if(XGetModuleSection(Globals::hModule, "INI", &buffer, &size)){
			if(CWriteFile(PATH_INI, buffer, size) != TRUE) {
				Utilities::PrintToLog("Could Not Write XeNoN.ini");
				return E_FAIL;
			}
			Utilities::PrintToLog("Successfully Wrote XeNoN.ini");
			return ERROR_SUCCESS;
		} else {
			Utilities::PrintToLog("Couldn't Find XeNoN.ini Section");
			return E_FAIL;
		}*/
		return ERROR_SUCCESS;
	}

	BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa) {
		BYTE scratch[256];
		DWORD val = pRsa->cqw << 3;
		if (val <= 0x200) {
			XeCryptBnQw_SwapDwQwLeBe((QWORD*)pbSig, (QWORD*)scratch, val >> 3);
			if (XeCryptBnQwNeRsaPubCrypt((QWORD*)scratch, (QWORD*)scratch, pRsa) == 0) return FALSE;
			XeCryptBnQw_SwapDwQwLeBe((QWORD*)scratch, (QWORD*)scratch, val >> 3);
			return XeCryptBnDwLePkcs1Verify((const PBYTE)pbHash, scratch, val);
		}
		else return FALSE;
	}

	VOID Reverse(PBYTE pbData, DWORD cbData) {
		DWORD dwMidpoint = cbData >> 1;
		DWORD dwReverseCounter = 0;
		PBYTE pbPtr = pbData;

		if (dwMidpoint) {
			while (dwReverseCounter < dwMidpoint) {
				DWORD i = (cbData - dwReverseCounter) - 1 & 0xFFFFFFFF;

				BYTE b1 = *pbPtr;
				BYTE b2 = pbData[i];
				*pbPtr = b2;
				pbData[i] = b1;

				dwReverseCounter++;
				pbPtr++;
			}
		}
	}

	VOID Reverse8(BYTE* Input, DWORD Length){
		BYTE* tmp = (BYTE*)XEncryptedAlloc(Length);
		DWORD num = Length - 8, num2 = 0;

		for(DWORD i = 0; i < (Length / 8); i++){
			for (DWORD j = 0; j < 8; j++){
				Input[num2 + j] = Input[num + j];
			}
			num -= 8;
			num2 += 8;
		}
		memcpy(Input, tmp, Length);
		XEncryptedFree(tmp);
	}

	BOOL SetLiveBlock(BOOL enable){
		DLAUNCHSETOPTVALBYNAME DLaunchSetOptValByName = (DLAUNCHSETOPTVALBYNAME)Utilities::ResolveFunction("launch.xex", Utilities::DL_ORDINALS_SETOPTVALBYNAME);
		DLAUNCHGETOPTVALBYNAME DLaunchGetOptValByName = (DLAUNCHGETOPTVALBYNAME)Utilities::ResolveFunction("launch.xex", Utilities::DL_ORDINALS_GETOPTVALBYNAME);

		DWORD val = (enable) ? 1 : 0;
		DWORD val2 = (enable) ? 1 : 0;

		BOOL ret = DLaunchSetOptValByName("liveblock", &val);
		BOOL ret1 = DLaunchSetOptValByName("livestrong", &val2);

		DLaunchGetOptValByName("liveblock", &val);
		DLaunchGetOptValByName("livestrong", &val2);
		Utilities::PrintToLog("Liveblock %s | Livestrong %s", (val==1) ? "Enabled" : "Disabled", (val2==1) ? "Enabled" : "Disabled");
		return (ret && ret1);
	}

	PCONSOLE_TYPE GetConsoleType(PBYTE KV, BOOL Type1) {
		BYTE Mobo = ((*(PBYTE)(KV + 0x9D1) << 4) & 0xF0) | (*(PBYTE)(KV + 0x9D2) & 0x0F);
		
		PBYTE CTArray;
		DWORD CTSize;
		XGetModuleSection(GetModuleHandle(NAME_MODULE), "CT", (PVOID*)&CTArray, &CTSize);

		if (Mobo < 0x10 && !Type1) return (PCONSOLE_TYPE)(CTArray + (5 * 0x30));
		else if (Mobo < 0x10) return (PCONSOLE_TYPE)(CTArray);
		else if (Mobo < 0x14) return (PCONSOLE_TYPE)(CTArray + (1 * 0x30));
		else if (Mobo < 0x18) return (PCONSOLE_TYPE)(CTArray + (2 * 0x30));
		else if (Mobo < 0x52) return (PCONSOLE_TYPE)(CTArray + (3 * 0x30));
		else if (Mobo < 0x58) return (PCONSOLE_TYPE)(CTArray + (4 * 0x30));
		else return (PCONSOLE_TYPE)(CTArray + (5 * 0x30));
	}

	VOID SpoofDriveOsig(PBYTE Osig, PBYTE Spoof){
		memcpy(Spoof, Osig, 0x24);
		if(memcmp(Spoof + 0x10, "DG-16D2S", 8) == 0)
			*(DWORD*)(Spoof + 0x20) = 0x30323531;
		if((memcmp(Spoof + 0x10, "DG-16D4S", 8) == 0) && (memcmp(Spoof + 0x20, "9504", 4) == 0))
			*(DWORD*)(Spoof + 0x20) = 0x30323732;
		if(memcmp(Spoof + 0x10, "VAD6038", 7) == 0) {
			BYTE NewVersion[0x6] = {0x30, 0x34, 0x34, 0x32, 0x31, 0x43};
			memcpy(Spoof + 0x18, NewVersion, 6);
		}
	}
}

namespace HVPeekPoke {

	#define HvxCall QWORD _declspec(naked)
	static HvxCall HvxExpansionInstall(DWORD PhysicalAddress, DWORD CodeSize) {
		if(Globals::IsDevkit) __asm { li r0, 0x70 }
		else __asm { li r0, 0x72 }
		__asm {
			sc
			blr
		}
	}
	static HvxCall HvxExpansionCall(DWORD ExpansionId, QWORD Param1 = 0, QWORD Param2 = 0, QWORD Param3 = 0, QWORD Param4 = 0) {
		if(Globals::IsDevkit) __asm { li r0, 0x71 }
		else __asm { li r0, 0x73 }
		__asm {
			sc
			blr
		}
	}
	
	HRESULT InitializeHvPeekPoke() {

		// Allocate physcial memory for this expansion
		VOID* pPhysExp = XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
		DWORD physExpAdd = (DWORD)MmGetPhysicalAddress(pPhysExp);

		// Copy over our expansion data
		ZeroMemory(pPhysExp, 0x1000);
		memcpy(pPhysExp, HvPeekPokeExp, sizeof(HvPeekPokeExp));

		// Now we can install our expansion
		HRESULT result = (HRESULT)HvxExpansionInstall(physExpAdd, 0x1000);

		// Free our allocated data
		XPhysicalFree(pPhysExp);

		// Return our install result
		return result;
	}
	
	BYTE HvPeekBYTE(QWORD Address) {
		return (BYTE)HvxExpansionCall(HvPeekPokeExpID, PEEK_BYTE, Address);
	}

	WORD HvPeekWORD(QWORD Address) {
		return (WORD)HvxExpansionCall(HvPeekPokeExpID, PEEK_WORD, Address);
	}

	DWORD HvPeekDWORD(QWORD Address) {
		return (DWORD)HvxExpansionCall(HvPeekPokeExpID, PEEK_DWORD, Address);
	}

	QWORD HvPeekQWORD(QWORD Address) {
		return HvxExpansionCall(HvPeekPokeExpID, PEEK_QWORD, Address);
	}
	
	HRESULT HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size) {	
	
		// Create a physical buffer to peek into
		VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
		ZeroMemory(data, Size);
	
		HRESULT result = (HRESULT)HvxExpansionCall(HvPeekPokeExpID, 
			PEEK_BYTES, Address, (QWORD)MmGetPhysicalAddress(data), Size);

		// If its successful copy it back
		if(result == S_OK) memcpy(Buffer, data, Size);

		// Free our physical data and return our result
		XPhysicalFree(data);
		return result;
	}

	HRESULT HvPokeBYTE(QWORD Address, BYTE Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_BYTE, Address, Value);
	}

	HRESULT HvPokeWORD(QWORD Address, WORD Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_WORD, Address, Value);
	}

	HRESULT HvPokeDWORD(QWORD Address, DWORD Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_DWORD, Address, Value);
	}

	HRESULT HvPokeQWORD(QWORD Address, QWORD Value) {
		return (HRESULT)HvxExpansionCall(HvPeekPokeExpID, POKE_QWORD, Address, Value);
	}

	HRESULT HvPokeBytes(QWORD Address, const void* Buffer, DWORD Size) {

		// Create a physical buffer to poke from
		VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
		memcpy(data, Buffer, Size);
	
		HRESULT result = (HRESULT)HvxExpansionCall(HvPeekPokeExpID, 
			POKE_BYTES, Address, (QWORD)MmGetPhysicalAddress(data), Size);

		// Free our physical data and return our result
		XPhysicalFree(data);
		return result;
	}

	QWORD HvGetFuseLine(BYTE fuseIndex){
		if (fuseIndex > 11 || fuseIndex < 0) return 0;
		return HvPeekQWORD(0x8000020000020000 + (fuseIndex * 0x200));
	}








	VOID HvDumpFromMemory(CHAR* FilePath) 
	{
		// Create our output file
		HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		// Read our our HV from memory
		BYTE hvPart[0x10000]; DWORD pageSize = 0x10000;DWORD x;
		QWORD address = 0;
		QWORD rtoc = 0x0000000200000000;
		for(x = 0; x < 4; x++) {
			DWORD bytesWritten  = 0;

			// Read our section from our HV
			ZeroMemory(hvPart, pageSize);
			HvPeekBytes(address, hvPart, pageSize);

			// Write out the section
			WriteFile(fHandle, hvPart, pageSize, &bytesWritten, NULL);

			// Now increase our address
			address += (rtoc + pageSize);
		}

		// Close our output file
		CloseHandle(fHandle);
	}


	VOID writeHVPriv( BYTE* src, UINT64 dest, DWORD size)
	{
		for (DWORD i = 0; i < size; i++)
		{
			BYTE data = *(BYTE*)src;
			HvxExpansionCall(0x48565050, 5, dest, data);
			src++;
			dest++;
		}
	}

	VOID readHVPriv( UINT64 src, BYTE* dest, DWORD size)
	{
		for (DWORD i = 0; i < size; i++)
		{
			dest[i] = (BYTE)HvxExpansionCall(0x48565050, 0, src);
			src++;
		}
	}
}

namespace Keyvault {

	BOOL VerifyKeyVault() {
		XECRYPT_HMACSHA_STATE hmacSha; 
		XeCryptHmacShaInit(&hmacSha, Globals::Spoofed_CPUKey, 0x10); 
		XeCryptHmacShaUpdate(&hmacSha, (BYTE*)&Globals::KeyVault.OddFeatures, 0xD4); 
		XeCryptHmacShaUpdate(&hmacSha, (BYTE*)&Globals::KeyVault.DvdKey, 0x1CF8); 
		XeCryptHmacShaUpdate(&hmacSha, (BYTE*)&Globals::KeyVault.CardeaCertificate, 0x2108); 
		XeCryptHmacShaFinal(&hmacSha, Globals::KVDigest, XECRYPT_SHA_DIGEST_SIZE);

		Globals::Type1KV = FALSE;
		DWORD Count = 0;
		for(DWORD x = 0; x < 0x100; x++) {
			if(Globals::KeyVault.KeyVaultSignature[x] == 0) Count++;
			if(Count > 0x50) {Globals::Type1KV = TRUE; break; }
		}

		//Utilities::CWriteFile("XeNoN:\\KVDigest.bin", Globals::KVDigest, 0x14);
		//Utilities::CWriteFile("XeNoN:\\KV_Dump.bin", &Globals::KeyVault, 0x4000);

		return Utilities::XeKeysPkcs1Verify(Globals::KVDigest, Globals::KeyVault.KeyVaultSignature, (XECRYPT_RSA*)Globals::MasterKey);
	}

	HRESULT SetKeyVault(BYTE* KeyVault) {
		memcpy(&Globals::KeyVault, KeyVault, 0x4000);
	
		Utilities::SetMemory((PVOID)0x8E03A000, &Globals::KeyVault.ConsoleCertificate, 0x1A8);
		if(Globals::IsDevkit) {
			Utilities::SetMemory((BYTE*)((*(DWORD*)0x81D6AF30) + 0x313C), &Globals::KeyVault.ConsoleCertificate, 0x1A8); // CXNetLogonTask * g_pXNetLogonTask handle // v16203
		}
		Utilities::SetMemory((PVOID)0x8E038020, &Globals::KeyVault.ConsoleCertificate.ConsoleId.abData, 5);

		BYTE newHash[XECRYPT_SHA_DIGEST_SIZE];
		XeCryptSha((BYTE*)0x8E038014, 0x3EC, NULL, NULL, NULL, NULL, newHash, XECRYPT_SHA_DIGEST_SIZE);
		Utilities::SetMemory((PVOID)0x8E038000, newHash, XECRYPT_SHA_DIGEST_SIZE);

		QWORD kvAddress = (Globals::IsDevkit) ? HVPeekPoke::HvPeekQWORD(hvKvPtrDev) : HVPeekPoke::HvPeekQWORD(hvKvPtrRetail);

		HVPeekPoke::HvPeekBytes(kvAddress + 0xD0, Globals::KeyVault.ConsoleObfuscationKey, 0x40);
		memcpy(Globals::KeyVault.RoamableObfuscationKey, !Globals::IsDevkit ? Globals::RetailKey19 : Globals::DeveloperKey19, 0x10);
		HVPeekPoke::HvPokeBytes(kvAddress, &Globals::KeyVault, 0x4000);

		
		Globals::FCRT = (Globals::KeyVault.OddFeatures & KV_Structure::ODD_POLICY_FLAG_CHECK_FIRMWARE) != 0 ? TRUE : FALSE;
		VerifyKeyVault();

		// All done
		return ERROR_SUCCESS;
	}

	HRESULT SetKeyVault(CHAR* FilePath) {
		Utilities::MemoryBuffer mbkv;
		if(!Utilities::CReadFile(FilePath, mbkv)) {
			return E_FAIL;
		}
		return SetKeyVault(mbkv.GetData());
	}
}