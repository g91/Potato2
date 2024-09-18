#include "stdafx.h"

namespace System {

	DWORD LastTitleID = 0;

	XEX_EXECUTION_ID* RtlImageXexHeaderFieldHook(VOID* HeaderBase, DWORD ImageKey){
		XEX_EXECUTION_ID* ExecID = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(HeaderBase, ImageKey);
		if (ImageKey == 0x40006 && ExecID){
			switch (ExecID->TitleID){
				case 0xFFFF0055: // Xex Menu
				case 0xC0DE9999: // Xex Menu alt
				case 0xFFFE07FF: // XShellXDK
				case 0xF5D20000: // FSD
				case 0xFFFF011D: // DashLaunch
				case 0xFFFEFF43: // Xell Launch GOD
				case 0xFEEDC0DE: // XYZProject
				case 0xFFED0707: // SNES360
				{
					Utilities::SetMemory(ExecID, &Globals::SpoofedExecutionId, sizeof(XEX_EXECUTION_ID));
					break;
				}
			}
		} else if (ImageKey == 0x40006 && !ExecID) {
			ExecID = &Globals::SpoofedExecutionId;
		}
		return ExecID;
	}

	NTSTATUS XexLoadImageHook(LPCSTR XexName, DWORD Flags, DWORD MinimumVersion, PHANDLE Handle) {
		HANDLE mHandle = NULL;
		NTSTATUS Result = XexLoadImage(XexName, Flags, MinimumVersion, &mHandle);
		if (Handle != NULL) *Handle = mHandle;
		if (NT_SUCCESS(Result)) HookXexLoad((PLDR_DATA_TABLE_ENTRY)mHandle);
		return Result;
	}

	/*NTSTATUS XexUnloadImageHook(HANDLE Handle) {
		DWORD LR = 0;
		__asm {
			mr LR, r12 
		}
		Utilities::PrintToLog("XexUnloadImage: 0x%08X", LR);
		XexUnloadImage(Handle);
	}*/

	NTSTATUS XexLoadExecutableHook(PCHAR XexName, PHANDLE Handle, DWORD Flags, DWORD MinimumVersion){
		HANDLE mHandle = NULL;
		NTSTATUS result = XexLoadExecutable(XexName, &mHandle, Flags, MinimumVersion);
		if (Handle != NULL) *Handle = mHandle;
		if (NT_SUCCESS(result)) HookXexLoad((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
		return result;
	}

	NTSTATUS XexLoadImageFromMemoryHook(PVOID Image, DWORD ImageSize, PCHAR ImageName, DWORD Flags, DWORD MinimumVersion, PHANDLE Handle) {
		Utilities::PrintToLog("Module Loading: %s", ImageName);
		//if (memcmp(ImageName, "xosc", 4) == 0) Utilities::CWriteFile("XeNoN:\\xosc9v2.xex", Image, ImageSize);
		//NTSTATUS Result = XexLoadImageFromMemory(Image, ImageSize, ImageName, Flags, MinimumVersion, Handle);
		//Utilities::PrintToLog("Result: 0x%08X", Result);
		return XexLoadImageFromMemory(Image, ImageSize, ImageName, Flags, MinimumVersion, Handle);
	}

	BOOL XexCheckExecutablePrivilegeHook(DWORD priv) {
		if (priv == 6) return TRUE;
		return XexCheckExecutablePrivilege(priv);
	}

	DWORD XSecurityCreateProcessHook(DWORD dwHardwareThread){
		return ERROR_SUCCESS;
	}

	VOID XSecurityCloseProcessHook(){ 
		return;
	}

	VOID __cdecl APCWorker(void* Arg1, void* Arg2, void* Arg3) {
		// Call our completion routine if we have one
		if(Arg2) ((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
	}

	DWORD XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
		// Queue our completion routine
		if(lpCompletionRoutine)	NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);
		// All done
		return ERROR_SUCCESS;
	}

	DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation) {
		if (pFailureInformation->dwSize == 0x14) {
			pFailureInformation->dwBlocksChecked = 0x64;
			pFailureInformation->dwFailedHashes = 0;
			pFailureInformation->dwFailedReads = 0;
			pFailureInformation->dwTotalBlocks = 0x64;
		}
		else if (pFailureInformation->dwSize == sizeof(XSECURITY_FAILURE_INFORMATION)) {
			pFailureInformation->dwBlocksChecked = 0x100;
			pFailureInformation->dwFailedHashes = 0;
			pFailureInformation->dwFailedReads = 0;
			pFailureInformation->dwTotalBlocks = 0x100;
			pFailureInformation->fComplete = TRUE;
		}
		else return ERROR_NOT_ENOUGH_MEMORY;
		return ERROR_SUCCESS;
	}

	DWORD XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress)
	{	
		// Check our module
		if(hand == GetModuleHandle(MODULE_XAM)) {
			switch(dwOrdinal) {
			case 0x9BB:
				*pvAddress = XSecurityCreateProcessHook;
				return 0;
			case 0x9BC:
				*pvAddress = XSecurityCloseProcessHook;
				return 0;
			case 0x9BD:
				*pvAddress = XSecurityVerifyHook;
				return 0;
			case 0x9BE:
				*pvAddress = XSecurityGetFailureInfoHook;
				return 0;
			}
		}
		// Call our real function if we aren't interested
		return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
	}

	typedef HRESULT (*pXamInputGetState)(QWORD r3,QWORD r4,QWORD r5);
	pXamInputGetState XamInputGetState = (pXamInputGetState)Utilities::ResolveFunction(MODULE_XAM, 401);

	static BOOL isFrozen = FALSE;
	HRESULT XamInputGetStateHook(QWORD r3,QWORD r4,QWORD r5){
		if(isFrozen){
			return 0;
		}
		HRESULT ret = XamInputGetState(r3, r4, r5);
		return ret;
	}

	VOID UnhookGuideLoad(){
		while (GetModuleHandle("Guide.MP.Purchase.xex") != 0) Sleep(500);
			Utilities::ApplyPatches((PVOID)Globals::MSP_UNDO);
	}

	HRESULT XamUserCheckPrivilegeHook(DWORD user_index, DWORD priv, PBOOL result){
		switch(priv){
			case XPRIVILEGE_MULTIPLAYER_SESSIONS:
			case XPRIVILEGE_COMMUNICATIONS:
			case XPRIVILEGE_PROFILE_VIEWING:
			case XPRIVILEGE_USER_CREATED_CONTENT:
			case XPRIVILEGE_PURCHASE_CONTENT:
			case XPRIVILEGE_PRESENCE:
			case XPRIVILEGE_TRADE_CONTENT:
			case XPRIVILEGE_VIDEO_COMMUNICATIONS:
			//case XPRIVILEGE_SOCIAL_NETWORK_SHARING:
			case XPRIVILEGE_CONTENT_AUTHOR:
			case XPRIVILEGE_UNSAFE_PROGRAMMING:
			case XPRIVILEGE_SHARE_CONTENT_OUTSIDE_LIVE:
			//case XPRIVILEGE_INTERNET_BROWSING:
				*result = TRUE;
				break;
			case XPRIVILEGE_COMMUNICATIONS_FRIENDS_ONLY:
			case XPRIVILEGE_PROFILE_VIEWING_FRIENDS_ONLY:
			case XPRIVILEGE_USER_CREATED_CONTENT_FRIENDS_ONLY:
			case XPRIVILEGE_PRESENCE_FRIENDS_ONLY:
			case XPRIVILEGE_VIDEO_COMMUNICATIONS_FRIENDS_ONLY:
				*result = FALSE;
			default:
				return XamUserCheckPrivilege(user_index, priv, result);
		}
		return ERROR_SUCCESS;
	}

	VOID HookXexLoad(PLDR_DATA_TABLE_ENTRY ModuleHandle){
		Utilities::PatchModuleImport(ModuleHandle, MODULE_KERNEL, 407, (DWORD)XexGetProcedureAddressHook);
		Utilities::PatchModuleImport(ModuleHandle, MODULE_KERNEL, 408, (DWORD)XexLoadExecutableHook);
		Utilities::PatchModuleImport(ModuleHandle, MODULE_KERNEL, 409, (DWORD)XexLoadImageHook);
		Utilities::PatchModuleImport(ModuleHandle, MODULE_XAM, 401, (DWORD)XamInputGetStateHook);

		//Utilities::PrintToLog("Module Loading: %ws", ModuleHandle->BaseDllName.Buffer);

		XEX_EXECUTION_ID* ExecutionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(ModuleHandle->XexHeaderBase, 0x00040006);
		if (ExecutionId == 0) return;

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"dash.xex") == 0){
			Globals::DashLoaded = TRUE;
			// Rename "sign in or out" Title
			// Update method: Dump from "C0000000" to "1FFF0FFF", use HxD Editor and search for hex: "43686f6f736520796f75722070726f66696c65" > "Choose your profile" in hexadecimal
			//BYTE text[] = {0x58, 0x65, 0x4E, 0x6F, 0x4E, 0x20, 0x31, 0x37, 0x35, 0x31, 0x31, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x20, 0x20, 0x57, 0x65, 0x6C, 0x63, 0x6F, 0x6D, 0x65, 0x20, 0x54, 0x6F, 0x20, 0x20, 0x00};
			//Utilities::SetMemory((LPVOID)0xC248DFFC, text, 35);
		}

		/*if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"Guide.MP.Purchase.xex") == 0) {
			Utilities::ApplyPatches((PVOID)Globals::MSP_APPLY);
			HANDLE hThread2; 
			DWORD threadId2;
			ExCreateThread(&hThread2, 0, &threadId2, (VOID*)XapiThreadStartup, (LPTHREAD_START_ROUTINE)UnhookGuideLoad, NULL, 0x2 | CREATE_SUSPENDED);
			XSetThreadProcessor(hThread2, 4);
			SetThreadPriority(hThread2, THREAD_PRIORITY_ABOVE_NORMAL);
			ResumeThread(hThread2);
		}*/

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0){
			LastTitleID = ExecutionId->TitleID;
			if(ExecutionId->TitleID == 0x4D5307E6){
				Utilities::PatchModuleImport("default.xex", MODULE_XAM, 0x212, (DWORD)XamUserCheckPrivilegeHook);
			}
		}
		
		/*if(ExecutionId->TitleID == Globals::FSD){
			Globals::DashLoaded = TRUE;
		}

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default.xex") == 0 ){
			LastTitleID = ExecutionId->TitleID;
			switch (ExecutionId->TitleID){
			case Globals::COD_BO3:
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::BlackOps3Init);
				break;
			case Globals::DEST:
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::DestinyInit);
				break;
			}

		}

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_mp.xex") == 0){
			LastTitleID = ExecutionId->TitleID;
			switch(ExecutionId->TitleID){
			case Globals::COD_GH:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::GhostInit);
				break;
			case Globals::COD_BO2:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::BlackOps2Init);
				break;
			case Globals::COD_AW:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::AdvancedWarfareInit);
				break;
			case Globals::COD_MW3:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::ModernWarfare3Init);
				break;
			case Globals::COD_BO1:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::BlackOps1Init);
				break;
			case Globals::COD_MW2:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::ModernWarfare2Init);
				break;
			case Globals::COD_WAW:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::WorldAtWarInit);
				break;
			case Globals::COD_MW1:
				Sleep(100);
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::ModernWarfare1Init);
				break;
			default:
				break;
			}
		}

		if (wcscmp(ModuleHandle->BaseDllName.Buffer, L"default_zm.xex") == 0){
			LastTitleID = ExecutionId->TitleID;
			switch(ExecutionId->TitleID){
			case Globals::COD_BO3:
				Utilities::ThreadMe((LPTHREAD_START_ROUTINE)Games::BlackOps3ZombiesInit);
				break;
			default:
				break;
			}
		}*/

	}

}