#include "stdafx.h"
#include "VdDisplay.h"

bool bDisplayOn = true;
typedef void(__cdecl * FUNCT_void_void_t)(void); // no return, no parameters
FUNCT_void_void_t VdTurnDisplayOff = (FUNCT_void_void_t)Utilities::ResolveFunction("xboxkrnl.exe", 477);
FUNCT_void_void_t VdTurnDisplayOn = (FUNCT_void_void_t)Utilities::ResolveFunction("xboxkrnl.exe", 478);

typedef void(_cdecl * VdSwap_t)(LPVOID buffer_ptr, LPVOID fetch_ptr, UINT unk2, UINT* unk3, UINT* unk4, LPDWORD frontbuffer_ptr, LPDWORD color_format_ptr, LPDWORD color_space_ptr, UINT* unk8, UINT* unk9);
VdSwap_t VdSwap = (VdSwap_t)Utilities::ResolveFunction("xboxkrnl.exe", 603);
void VdSwapHook(LPVOID buffer_ptr, LPVOID fetch_ptr, UINT unk2, UINT* unk3, UINT* unk4, LPDWORD frontbuffer_ptr, LPDWORD color_format_ptr, LPDWORD color_space_ptr, UINT* unk8, UINT* unk9)
{
	// seems to get called once per frame, so i think i have it right
	printf("VdSwap\n");

	VdSwap(buffer_ptr, fetch_ptr, unk2, unk3, unk4, frontbuffer_ptr, color_format_ptr, color_space_ptr, unk8, unk9);
}

namespace VD
{
	void VdTurnDisplayON()
	{
		VdTurnDisplayOn();
	}

	void VdTurnDisplayOFF()
	{
		VdTurnDisplayOff();
	}
}