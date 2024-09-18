#pragma once
#include "stdafx.h"

namespace dump
{
	void DumpHv();
	void getCB_AKey(PBYTE Keybuf);
	void getCB_BKey(PBYTE Keybuf);
	void DumpCB_A();
	void DumpCB_B();
	void DumpData(LPCSTR filename);
	void DumpCache();
	bool DumpArea(QWORD address, DWORD size, LPCSTR filename);
	void DumpXexModule(char* modName);
	void DumpExpansion(int dwExpansion);

	QWORD getFuseline(DWORD fuse);
	void getCPUKey(BYTE* KeyBuf);
	void DumpFuses();
}