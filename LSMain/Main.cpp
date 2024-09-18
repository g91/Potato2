#include "stdafx.h"
#include "Test.h"
#include <xhttp.h>
#include <unordered_map> 

namespace Main {

	VOID __declspec(naked) XHTTPOpenRequestUsingMemoryHookStub(HINTERNET Connect, const CHAR* Verb, const CHAR* ObjectName, const CHAR* Version, const CHAR* Referrer, const CHAR** Reserved, DWORD Flags){
		__asm
		{
			li r3, 0
			nop
			nop
			nop
			nop
			nop
			nop
			blr
		}
	}

	typedef void(*tXHTTPOpenRequestUsingMemory)(HINTERNET Connect, const CHAR* Verb, const CHAR* ObjectName, const CHAR* Version, const CHAR* Referrer, const CHAR** Reserved, DWORD Flags);
	tXHTTPOpenRequestUsingMemory OriginalXHTTPOpenRequestUsingMemory;


	void XHTTPOpenRequestUsingMemoryHook(HINTERNET Connect, const CHAR* Verb, const CHAR* ObjectName, const CHAR* Version, const CHAR* Referrer, const CHAR** Reserved, DWORD Flags) {
			Utilities::PrintToLog("Called: XHTTPOpenRequestUsingMemoryHook\r\n");


			//if (strstr(ObjectName, "dashhome.xml")) {
			//	ObjectName = "/get-manifest/dashhome.xml";
			//	HUD::bNullHeader = true;
			//}
			//if (strstr(ObjectName, "XeMenu.xml")) {
			//	ObjectName = "/get-manifest/XeMenu.xml";
			//	HUD::bNullHeader = true;
			//}

		XHTTPOpenRequestUsingMemoryHookStub(Connect, Verb, ObjectName, Version, Referrer, Reserved, Flags);
	}

	CHAR XMLIP[] = { '1', '9', '8', '.', '9', '8', '.', '5', '7', '.', '2', '8','\0' };


	VOID __declspec(naked) XHTTPConnectHookStub(HINTERNET Session, const CHAR* ServerName, INTERNET_PORT ServerPort, DWORD Flags){
		__asm
		{
			li r3, 0
			nop
			nop
			nop
			nop
			nop
			nop
			blr
		}
	}

	typedef void(*tXHTTPConnect)(HINTERNET Session, const CHAR* ServerName, INTERNET_PORT ServerPort, DWORD Flags);
	tXHTTPConnect OriginalXHTTPConnect;

	void XHTTPConnectHook(HINTERNET Session, const CHAR* ServerName, INTERNET_PORT ServerPort, DWORD Flags) {
		Utilities::PrintToLog("Called: XHTTPConnectHook\r\n");
			//if (strcmp(ServerName, "manifest.xboxlive.com") == 0)
			//	ServerName = XMLIP;
			//	ServerPort = 1337;
			//	Flags = 1;
		XHTTPConnectHookStub(Session, ServerName, ServerPort, Flags);
	}

	VOID __declspec(naked) XHTTPSendRequestHookStub(HINTERNET Request, const CHAR* Headers, DWORD HeadersLength, const void* lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context){
		__asm
		{
			li r3, 0
			nop
			nop
			nop
			nop
			nop
			nop
			blr
		}
	}

	typedef void(*tXHTTPSendRequest)(HINTERNET Request, const CHAR* Headers, DWORD HeadersLength, const void* lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context);
	tXHTTPSendRequest OriginalXHTTPSendRequest;

	void XHTTPSendRequestHook(HINTERNET Request, const CHAR* Headers, DWORD HeadersLength, const void* lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context) {
		Utilities::PrintToLog("Called: XHTTPSendRequestHook\r\n");


		XHTTPSendRequestHookStub(Request, Headers, HeadersLength, lpOptional, OptionalLength, TotalLength, Context);
	}



	VOID __declspec(naked) CXnIp_IpXmitSecMsgHookStub(DWORD r3, XNCALLER_TYPE Xnc, PDWORD CXnIp_CSecReg, USHORT r6, PBYTE pbBuffer, DWORD dwSize, PVOID r9, DWORD r10){
		__asm
		{
			li r3, 0
			nop
			nop
			nop
			nop
			nop
			nop
			blr
		}
	}

	typedef VOID(*tCXnIp_IpXmitSecMsg)(DWORD r3, XNCALLER_TYPE xnc, PDWORD CXnIp_CSecReg, USHORT r6, PBYTE dataBuff, DWORD size, PVOID r9, DWORD r10);
	VOID CXnIp_IpXmitSecMsgHook(DWORD r3, XNCALLER_TYPE Xnc, PDWORD CXnIp_CSecReg, USHORT r6, PBYTE pbBuffer, DWORD dwSize, PVOID r9, DWORD r10) {
		if (r6 == 0xA53 && dwSize == 0x128) {
			printf("IpXmitSecMsg: XKEBuffer\r\n");
			//memcpy(Globals::IPXKEBuffer, pbBuffer, 0x128);
			//Globals::DumpXKE = TRUE;
			if (memcmp(pbBuffer + 0x28, Globals::XKEBuffer + 0x20, 0xE0) != 0){
				memcpy(pbBuffer + 0x28, Globals::XKEBuffer + 0x20, 0xE0);
			}
		}

		if (r6 == 0xF53 && dwSize == 0x404) {
			printf("IpXmitSecMsg: XOSCBuffer\r\n");
			//memcpy(Globals::IPXOSCBuffer, pbBuffer, 0x404);
			//Globals::DumpXOSC = TRUE;
			if (memcmp(pbBuffer + 4, Globals::XOSCBuffer, 0x400) != 0){
				memcpy(pbBuffer + 4, Globals::XOSCBuffer, 0x400);
			}
		}

		return CXnIp_IpXmitSecMsgHookStub(r3, Xnc, CXnIp_CSecReg, r6, pbBuffer, dwSize, r9, r10);
	}

	HRESULT Mount_Drive(){
		if ((XboxHardwareInfo->Flags & 0x20) == 0x20){
			if (Utilities::CreateSymbolicLink(NAME_MOUNT, NAME_HDD, TRUE) != ERROR_SUCCESS) {
				return E_FAIL;
			}
		} else {
			if (Utilities::CreateSymbolicLink(NAME_MOUNT, NAME_USB, TRUE) != ERROR_SUCCESS){
				return E_FAIL;
			}
		}

		#ifdef _MOUNT_EXTRA
		Utilities::CreateSymbolicLink("SysAux:", "\\Device\\Harddisk0\\SystemAuxPartition\\", FALSE);
		Utilities::CreateSymbolicLink("SysExt:", "\\Device\\Harddisk0\\SystemExtPartition\\", FALSE);
		Utilities::CreateSymbolicLink("DEVKIT:", "\\Device\\Harddisk0\\Partition1\\DEVKIT", FALSE);
		Utilities::CreateSymbolicLink("Flash:", "\\Device\\FLASH", FALSE);
		
		#endif
		return ERROR_SUCCESS;
	}

	HRESULT Process_KV() {
		if (Utilities::FileExists(PATH_KEYVAULT)) {
			if(Keyvault::SetKeyVault(PATH_KEYVAULT) == ERROR_SUCCESS) {
				#ifdef _DEBUG
				Utilities::PrintToLog("Using File KV.Bin");
				#endif
				return ERROR_SUCCESS;
			}
		}

		BYTE* kv = (BYTE*)malloc(0x4000);
		if(HVPeekPoke::HvPeekBytes(HVPeekPoke::HvPeekQWORD(hvKvPtrRetail), kv, 0x4000) == ERROR_SUCCESS){
			if(Keyvault::SetKeyVault(kv) == ERROR_SUCCESS) {
				#ifdef _DEBUG
				Utilities::PrintToLog("Warn: KV.bin Not Found. Using Internal.");
				#endif
				free(kv);
				return ERROR_SUCCESS;
			}
		}

		free(kv);
		return E_FAIL;
	}


	char vaBuffer[0x1000];
	char* va(const char* fmt, ...) {
		memset(vaBuffer, 0, 0x1000);
		va_list ap;
		va_start(ap, fmt);
		RtlVsprintf(vaBuffer, fmt, ap);
		va_end(ap);
		return vaBuffer;
	}

	PWCHAR vaw(const char* Text, ...) {
		CHAR Buffer[0x1000];
		CHAR MessageBuffer[0x100];
		static WCHAR Message[0x100];

		va_list pArgList;
		va_start(pArgList, Text);
		RtlVsprintf(Buffer, Text, pArgList);
		va_end(pArgList);

		RtlSprintf(MessageBuffer, Buffer);
		mbstowcs(Message, MessageBuffer, strlen(MessageBuffer) + 1);

		ZeroMemory(Buffer, sizeof(Buffer));
		ZeroMemory(MessageBuffer, sizeof(MessageBuffer));

		return Message;
	}

	HRESULT Setup_Hooks() {
		if(Globals::IsDevkit){
			Utilities::ApplyPatches((PVOID)Globals::PATCH_DATA_KXAM_DEVKIT);
			//Utilities::ApplyPatches((PVOID)Globals::PATCH_DATA_KXAM_DEVKIT2);
			Utilities::PatchInJump((DWORD*)0x8169C908, (DWORD)Challenge::XamLoaderExecuteAsyncChallengeHook, false);

			*(DWORD*)0x817a69CC = 0x60000000;
			*(DWORD*)0x8180dd28 = 0x60000000;



			wchar_t buffer[15];
			lstrcpyW(buffer, L"%s@");
			lstrcatW(buffer, vaw("d0a.net"));

			lstrcpyW((wchar_t*)0x8160E254, buffer);
			lstrcpyW((wchar_t*)0x8160E23C, vaw("123456"));

			char buffer2[16];
			strcpy(buffer2, "%ws@");
			strcat(buffer2, "d0a.net");

			strcpy((char*)0x8160D8E4, buffer2);
			strcpy((char*)0x8160D898, va("@%s", "d0a.net"));
			strcpy((char*)0x8160D858, "123456");
		} else {
			*(DWORD*)0x81682544 = 0x60000000; //nop EvaluateContent Serial Check
			*(DWORD*)0x816798EC = 0x60000000; //nop MmGetPhysicalAddress For Challenge
			*(DWORD*)0x8167F978 = 0x38600000; //XContent::ContentEvaluateLicense return ERROR_SUCCESS
			*(DWORD*)0x8167C4B4 = 0x38600000; //XContent::VerifySignature return ERROR_SUCCESS
			*(DWORD*)0x8192BDA8 = 0x38600000; //ProfileEmbeddedContent::Validate return ERROR_SUCCESS
			*(DWORD*)0x816DA428 = 0x4E800020; //XampUserCheckLastSignedInConsoleStartupProc return
			*(DWORD*)0x816DCCC8 = 0x480000CC; //XampUserReportLogonFailure set LogonFail_Other
			

			*(DWORD*)0x81A3CD60 = 0x38600001; //Gold Spoof
			*(DWORD*)0x816DAC84 = 0x38600006; //Gold Bar

			//XampUserReportLogonFailure 0x816DCB10 NEED TO HOOK 90E1E488 NiNJA
			Utilities::PatchInJump((DWORD*)0x8169CD98, (DWORD)Challenge::XamLoaderExecuteAsyncChallengeHook, false);

		}
		//Utilities::ThreadMe((LPTHREAD_START_ROUTINE)DumpThread);
		Utilities::HookFunctionStart((PDWORD)(Globals::IsDevkit ? 0x8187D280 : 0x8174ED98), (PDWORD)CXnIp_IpXmitSecMsgHookStub, (DWORD)CXnIp_IpXmitSecMsgHook); //17489 Devkit + 17559
		
	
		//Setup Variables
		DWORD Version = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (XboxKrnlVersion->Build << 8) | (XboxKrnlVersion->Qfe);
		ZeroMemory(&Globals::SpoofedExecutionId, sizeof(XEX_EXECUTION_ID));
		Globals::SpoofedExecutionId.Version = Version;
		Globals::SpoofedExecutionId.BaseVersion = Version;
		Globals::SpoofedExecutionId.TitleID = 0xFFFE07D1;

		//Hooks
		if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 0x12B, (DWORD)System::RtlImageXexHeaderFieldHook) != S_OK) return S_FALSE;
		if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 404, (DWORD)System::XexCheckExecutablePrivilegeHook) != S_OK) return S_FALSE;
		if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 408, (DWORD)System::XexLoadExecutableHook) != S_OK) return S_FALSE;
		if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 409, (DWORD)System::XexLoadImageHook) != S_OK) return S_FALSE;
		if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 410, (DWORD)System::XexLoadImageFromMemoryHook) != S_OK) return S_FALSE;
		//if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 417, (DWORD)System::XexUnloadImageHook) != S_OK) return S_FALSE;
		if (Utilities::PatchModuleImport(MODULE_XAM, MODULE_KERNEL, 0x25F, (DWORD)Challenge::XeKeysExecuteHook) != S_OK) return S_FALSE;
		return ERROR_SUCCESS;
	}

	HRESULT Initialize() {

		//Mount run path
		if(Mount_Drive() != ERROR_SUCCESS){
			#ifdef _DEBUG
			Utilities::PrintToLog("Could not mount drives.");
			#endif
			return E_FAIL;
		}

		//remove last log
		remove(PATH_LOG);

		//Kernel Version Check
		if(XboxKrnlVersion->Build != SUPPORTED_VERSION){
			#ifdef _DEBUG
			Utilities::PrintToLog("Unsupported Kernel Version: %d Expected: %d", XboxKrnlVersion->Build, SUPPORTED_VERSION);
			#endif
			return E_NOTIMPL;
		}

		//Devkit Check (Not Supported)
		Globals::IsDevkit =  *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE;
		Utilities::PrintToLog("Running on %s", Globals::IsDevkit ? "Devkit" : "Retail");

		//check xex name
		if(!GetModuleHandle(NAME_MODULE)){
			#ifdef _DEBUG
			Utilities::PrintToLog("Rename XEX back to XeNoN.xex");
			#endif
			return E_FAIL;
		}

		Test::Test();


		//process CPUKey.bin
		Utilities::PrintToLog("ProcessCPUKeyBin strat");
		if(Utilities::ProcessCPUKeyBin(PATH_CPUKEYB) != ERROR_SUCCESS) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Could Not Process CPUKey.bin Or Use Internal.");
			#endif
			return E_FAIL;
		}

		//Initial Hypervisor Expansion
		Utilities::PrintToLog("InitializeHvPeekPoke strat");
		if(HVPeekPoke::InitializeHvPeekPoke() != ERROR_SUCCESS) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Could Not Apply Hypervisor Expansion.");
			#endif
			return E_FAIL;
		}

		//read real cpukey
		Utilities::PrintToLog("ProcessCPUKeyFuse strat");
		if(Utilities::ProcessCPUKeyFuse() != ERROR_SUCCESS) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Could Not Fetch CPUKey From Console.");
			#endif
			return E_FAIL;
		}
		
		Utilities::PrintToLog("Sleep strat");
		if(Globals::IsDevkit) Sleep(10000);

	
		
		Utilities::PrintToLog("Dumped_HV start");
		//HVPeekPoke::HvPeekBytes(0x8000010000000000, Globals::Dumped_HV, 0xFFFF);
		HVPeekPoke::readHVPriv(0x8000010000000000, Globals::Dumped_HV, 0xFFFF);
		//HVPeekPoke::HvPeekBytes(0x8000010200010000, (Globals::Dumped_HV + 0x10000), 0xFFFF);
		HVPeekPoke::readHVPriv(0x8000010200010000, (Globals::Dumped_HV + 0x10000), 0xFFFF);
		//HVPeekPoke::HvPeekBytes(0x8000010400020000, (Globals::Dumped_HV + 0x20000), 0xFFFF);
		HVPeekPoke::readHVPriv(0x8000010400020000, (Globals::Dumped_HV + 0x20000), 0xFFFF);
		//HVPeekPoke::HvPeekBytes(0x8000010600030000, (Globals::Dumped_HV + 0x30000), 0xFFFF);
		HVPeekPoke::readHVPriv(0x8000010600030000, (Globals::Dumped_HV + 0x30000), 0xFFFF);
		Utilities::PrintToLog("Dumped_HV stop");

		BYTE SMC[0x5];
		BYTE MSG[0x5] = {0x12, 0, 0, 0, 0};
		HalSendSMCMessage(MSG, SMC);
		Utilities::CWriteFile("XeNoN:\\XeDumps\\SMCVersion.bin", SMC, 0x5);

		BYTE FuseDigest[0x10];
		memcpy(FuseDigest, (PBYTE)0x8E03AA50, 0x10);
		Utilities::CWriteFile("XeNoN:\\XeDumps\\FuseDigest.bin", FuseDigest, 0x10);

		/*BYTE data[0x100] = { 0 };
		HalReadWritePCISpace(0, 2, 0, 0, data, 0x100, 0);
		QWORD r9 = ((((*(PBYTE)(data + 0x8) & ~0xFFFF00) | ((*(PSHORT)(data + 0x2) << 8) & 0xFFFF00))) << 8) & 0xFFFFFFFFFFFFFFFF;
		QWORD r10 = ((((*(PBYTE)(data + 0xB) & ~0xFFFF00) | ((*(PSHORT)(data + 0x4) << 8) & 0xFFFF00))) << 8) & 0xFFFFFFFFFFFFFFFF;
		QWORD PCIeHardwareInfo = ((((r9 | XboxHardwareInfo->PCIBridgeRevisionID) << 32) | r10) | *(PBYTE)(data + 0xA));
		Utilities::CWriteFile("XeNoN:\\XeDumps\\PCIeRevision.bin", &PCIeHardwareInfo, 0x8);*/

		//Sockets::SetupSockets();

		//setup all hooks
		Utilities::PrintToLog("Setup_Hooks strat");
		if(Setup_Hooks() != ERROR_SUCCESS) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Could Not Apply System Hooks.");
			#endif
			return E_FAIL;
		}

			//Utilities::PrintToLog("SetLiveBlock FALSE");
			//Utilities::SetLiveBlock(FALSE);


		//read kv.bin or use internal
		Utilities::PrintToLog("Process_KV strat");
		if(Process_KV() != ERROR_SUCCESS){
			#ifdef _DEBUG
			Utilities::PrintToLog("Failed To Read KV.bin Or Use Internal.");
			#endif
			return E_FAIL;
		}

		Utilities::PrintToLog("SetMacAddress strat");
		if (Utilities::SetMacAddress() != ERROR_SUCCESS) {
			#ifdef _DEBUG
			Utilities::PrintToLog("Failed To Set Mac Address For KV.");
			#endif
			return E_FAIL;
		}

		//reset xam cache (flags/fails)
		//XamCacheReset(XAM_CACHE_TICKETS);
		//XamCacheReset(XAM_CACHE_ALL);

		Globals::Initialized = TRUE;
		
		Utilities::PrintToLog("Init Success");
		return ERROR_SUCCESS;
	}
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	if ( dwReason == DLL_PROCESS_ATTACH ) {
		Globals::hModule = hModule;

		if(Utilities::IsTrayOpen()){
			Utilities::SetLiveBlock(TRUE);
			return TRUE;
		}

		if (Main::Initialize() != ERROR_SUCCESS){
			Utilities::SetLiveBlock(TRUE);
			Sleep(3000);
			HalReturnToFirmware(HalFatalErrorRebootRoutine); //reboot something failed
		}
	}
	return TRUE;
}
