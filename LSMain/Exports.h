#pragma once

#include "stdafx.h"

extern BYTE pbHook0Buffer[0x10000];
extern BYTE pbHook71Buffer[0x10000];

namespace Exports
{
	void MiscTest();				// 1
	void DumpCacheExp();			// 2 - wrapper for function in dump namespace
	void XNotifyTime();				// 3
	void DumpHvExp();				// 4 - wrapper for function in dump namespace
	void Dump2blArea();				// 5
	void DumpChalData();			// 6
	void ExecuteFile(DWORD rSize);	// 7
	void DumpFuse();				// 8
}