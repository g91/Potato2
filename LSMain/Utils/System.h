#include "stdafx.h"

namespace System {

	XEX_EXECUTION_ID* RtlImageXexHeaderFieldHook(VOID* HeaderBase, DWORD ImageKey);
	HRESULT XamUserCheckPrivilegeHook(DWORD user_index, DWORD priv, PBOOL result);
	NTSTATUS XexLoadImageHook(LPCSTR XexName, DWORD Flags, DWORD MinimumVersion, PHANDLE Handle);
	//NTSTATUS XexUnloadImageHook(HANDLE Handle);
	NTSTATUS XexLoadExecutableHook(PCHAR XexName, PHANDLE Handle, DWORD Flags, DWORD MinimumVersion);
	NTSTATUS XexLoadImageFromMemoryHook(PVOID Image, DWORD ImageSize, PCHAR ImageName, DWORD Flags, DWORD MinimumVersion, PHANDLE Handle);
	BOOL XexCheckExecutablePrivilegeHook(DWORD priv);
	DWORD XSecurityCreateProcessHook(DWORD dwHardwareThread);
	VOID XSecurityCloseProcessHook();
	VOID __cdecl APCWorker(void* Arg1, void* Arg2, void* Arg3);
	DWORD XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	DWORD XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation);
	DWORD XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress);
	HRESULT XamInputGetStateHook(QWORD r3,QWORD r4,QWORD r5);
	VOID HookXexLoad(PLDR_DATA_TABLE_ENTRY ModuleHandle);

}