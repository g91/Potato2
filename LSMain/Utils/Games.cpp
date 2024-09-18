#include "stdafx.h"

namespace Games {

	VOID BlackOps3Init(){
		DoBypass(BO3_BYPASS, Globals::GAME_ID::BO3, "Black Ops 3", "default.xex");
		Sleep(3000);
		DoMenu(BO3_MENU, "Black Ops 3");
	}

	VOID BlackOps3ZombiesInit(){
		DoBypass(BO3Z_BYPASS, Globals::GAME_ID::BO3Z, "Black Ops 3 Zombies", "default_zm.xex");
	}

	VOID BlackOps2Init(){
		DoBypass(BO2_BYPASS, Globals::GAME_ID::BO2, "Black Ops 2", "default_mp.xex");
		Sleep(3000);
		DoMenu(BO2_MENU, "Black Ops 2");
	}

	VOID BlackOps1Init(){
		Sleep(3000);
		DoMenu(BO1_MENU, "Black Ops 1");
	}

	VOID WorldAtWarInit(){
		Sleep(3000);
		DoMenu(WAW_MENU, "World At War");
	}

	VOID AdvancedWarfareInit(){
		DoBypass(AW_BYPASS, Globals::GAME_ID::AW, "Advanced Warfare", "default_mp.xex");
		Sleep(3000);
		DoMenu(AW_MENU, "Advanced Warfare");
	}

	VOID GhostInit(){
		DoBypass(BO2_BYPASS, Globals::GAME_ID::BO3, "Ghost", "default_mp.xex");
		Sleep(3000);
		DoMenu(GHOST_MENU, "Ghost");
	}

	VOID ModernWarfare3Init(){
		Sleep(3000);
		DoMenu(MW3_MENU, "Ghost");
	}

	VOID ModernWarfare2Init(){
		Sleep(3000);
		DoMenu(MW2_MENU, "Ghost");
	}

	VOID ModernWarfare1Init(){
		Sleep(3000);
		DoMenu(MW1_MENU, "Ghost");
	}

	VOID DestinyInit(){
		//fuck destiny?
	}

	VOID DoBypass(std::string Section, Globals::GAME_ID Game, std::string Name, char* Module){
		//BYPASS
		if(Globals::Ini.GetInteger(SECTION, Section, 1)){
			if (GameUtilities::PatchGameFromServer(Game) == ERROR_SUCCESS){
				wchar_t buff[100];
				swprintf(buff, L"LiquidSky - %s\nChallenges Spoofed!", Name);
				XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, 0, 2, buff, 0);
				Utilities::PatchModuleImport(Module, MODULE_KERNEL, 405, (DWORD)GameUtilities::XexGetModuleHandleHook);
				Utilities::PatchModuleImport(Module, MODULE_XAM, 64, (DWORD)GameUtilities::NetDll_XNetXnAddrToMachineIdHook);
			}
		} else { 
			wchar_t buff[100];
			swprintf(buff, L"LiquidSky - You have turned off the\n%s Bypass!", Name);
			XNotifyQueueUI(XNOTIFYUI_TYPE_AVOID_REVIEW, 0, 2, buff, 0); 
		}
	}

	VOID DoMenu(std::string Section, std::string Name){
		if(Globals::Ini.GetInteger(SECTION, Section, 1)){
			if(GetModuleHandle("LSM.xex") != 0){
				LOADMENU LoadMenu = (LOADMENU)Utilities::ResolveFunction("LSM.xex", 1);
				LoadMenu(Globals::hModule, GetModuleHandle("LSM.xex"));
			} else {
				XNotifyQueueUI(XNOTIFYUI_TYPE_AVOID_REVIEW, 0, 2, L"LiquidSky - An error occurred!", 0);
			}
		} else { 
			wchar_t buff[100];
			swprintf(buff, L"LiquidSky - You have turned off the\n%s Menu!", Name);
			XNotifyQueueUI(XNOTIFYUI_TYPE_AVOID_REVIEW, 0, 2, buff, 0); 
		}
	}

}