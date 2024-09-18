#include "stdafx.h"

namespace Games {

	typedef VOID(*LOADMENU)(HANDLE m, HANDLE t); //to be changed to provide struct pointers

	VOID BlackOps3Init();
	VOID BlackOps3ZombiesInit();
	VOID BlackOps2Init();
	VOID BlackOps1Init();
	VOID WorldAtWarInit();
	VOID AdvancedWarfareInit();
	VOID GhostInit();
	VOID ModernWarfare3Init();
	VOID ModernWarfare2Init();
	VOID ModernWarfare1Init();
	VOID DestinyInit();

	VOID DoBypass(std::string Section, Globals::GAME_ID Game, std::string Name, char* Module);
	VOID DoMenu(std::string Section, std::string Name);

}