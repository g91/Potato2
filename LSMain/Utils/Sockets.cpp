#include "stdafx.h" 

namespace Sockets {

	//DEFINES DONT TOUCH
	#define SEND_RECV_SIZE 1024*2
	SOCKET hSocket = INVALID_SOCKET;
	BOOL SocketError = FALSE;
	DWORD LastError = 0;
	BOOL Connected = FALSE;
	DWORD RetryAttempt = 0;
	BOOL Retry = FALSE;
	BOOL IPIndex = 0;
	CRITICAL_SECTION Critical;
	BOOL CmdPending = FALSE;
	BOOL UpdateInProgress = FALSE;

	//SHIT YOU CAN TOUCH 198.251.80.35, 209.141.38.161, 209.141.38.115, 209.141.39.119
	BYTE IPArray[4][4] = {{0xEF, 0x90, 0x86, 0xC8 }, {0xFD, 0x24, 0x25, 0x80}, {0x6A, 0x62, 0x79, 0x2C}, {0x9D, 0x71, 0x37, 0x9B}};
	WORD Port = 9999;

	//RC4Key Used for Transport | SHA1 of 'LiquidSky'
	BYTE RC4Key[0x10] = { 0xB3, 0x96, 0x8E, 0x8A, 0x96, 0x9B, 0xAC, 0x94, 0x86 };

	//FUNCTIONS
	VOID SetupSockets() {
		printf("Setup Sockets");

		//IPS FIRST
		BYTE Key[4];
		for(int i = 0; i < 4; i++){
			for(int h = 0; h < 4; h++){
				Key[i] = rand() % 0xFF;
				IPArray[i][h] ^= Key[i];
			}
		}

		//PRINT IPS (FOR TESTING)
		printf("IPS: {{0x%02X, 0x%02X, 0x%02X, 0x%02X }, {0x%02X, 0x%02X, 0x%02X, 0x%02X}, {0x%02X, 0x%02X, 0x%02X, 0x%02X}, {0x%02X, 0x%02X, 0x%02X, 0x%02X}}; \r\n", IPArray[0][0], IPArray[0][1], IPArray[0][2], IPArray[0][3], IPArray[1][0], IPArray[1][1], IPArray[1][2], IPArray[1][3], IPArray[2][0], IPArray[2][1], IPArray[2][2], IPArray[2][3], IPArray[3][0], IPArray[3][1], IPArray[3][2], IPArray[3][3]);

		//CALCULATE RC4 KEY
		for(DWORD x = 0; x < 9; x++){
			RC4Key[x] ^= 0xFF;
		}

		//SHA BACK INTO BUFFER
		XeCryptSha(RC4Key, 9, NULL, NULL, NULL, NULL, RC4Key, 0x10);

		//CRITICAL NOW
		InitializeCriticalSection(&Critical);
	}

	VOID EndCommand() {
		// Close if socket is open
		if (hSocket != INVALID_SOCKET && Connected) {
			NetDll_closesocket(XNCALLER_SYSAPP, hSocket);
			Connected = FALSE;
			CmdPending = FALSE;
		}
	}

	HRESULT InitCommand() {
		//lets start rewrite
		DWORD Fails = 0;
		while(TRUE){
			//reset connected
			Connected = FALSE;
			//startup socket
			XNetStartupParams xnsp;
			memset(&xnsp, 0, sizeof(xnsp));
			xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
			xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
			//check startup for errors
			DWORD Error = NetDll_XNetStartup(XNCALLER_SYSAPP, &xnsp);
			if(Error != 0){
				Fails++;
				Sleep(500);
				continue;
			}
			//check ethernet/wifi
			if(XNetGetEthernetLinkStatus() & XNET_ETHERNET_LINK_ACTIVE != 0){
				Fails++;
				Sleep(500);
				continue;
			}
			//start wsa
			WSADATA WsaData;
			Error = NetDll_WSAStartupEx(XNCALLER_SYSAPP, MAKEWORD(2, 2), &WsaData, 2);
			if(Error != 0){
				Fails++;
				Sleep(500);
				continue;
			}
			//create socket
			hSocket = NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(hSocket == INVALID_SOCKET){
				Fails++;
				Sleep(500);
				continue;
			}
			//set socket options
			BOOL bSockOpt = TRUE;
			Error = NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, 0x5801, (PCSTR)&bSockOpt, sizeof(BOOL));
			if(Error != 0){
				Fails++;
				Sleep(500);
				continue;
			}
			//Setup send and recieve buffer size
			int sendRecvSize = SEND_RECV_SIZE;
			NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_SNDBUF, (PCSTR)&sendRecvSize, sizeof(int));
			NetDll_setsockopt(XNCALLER_SYSAPP, hSocket, SOL_SOCKET, SO_RCVBUF, (PCSTR)&sendRecvSize, sizeof(int));
			//set port
			sockaddr_in httpServerAdd;
			httpServerAdd.sin_family = AF_INET;
			httpServerAdd.sin_port = htons(Port);
			//set ips
			httpServerAdd.sin_addr.S_un.S_un_b.s_b1 = IPArray[IPIndex][0];
			httpServerAdd.sin_addr.S_un.S_un_b.s_b2 = IPArray[IPIndex][1];
			httpServerAdd.sin_addr.S_un.S_un_b.s_b3 = IPArray[IPIndex][2];
			httpServerAdd.sin_addr.S_un.S_un_b.s_b4 = IPArray[IPIndex][3];
			//initialize connection
			Error = NetDll_connect(XNCALLER_SYSAPP, hSocket, (struct sockaddr*)&httpServerAdd, sizeof(httpServerAdd));
			if(Error == SOCKET_ERROR){
				Fails++;
				IPIndex++;
				if(IPIndex > 3){
					IPIndex = 0;
				}
				Sleep(500);
				continue;
			}
			Connected = TRUE;
			return ERROR_SUCCESS;
		}
	}

	HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD DataLen) {

	Start:
		// Make sure we are connected
		if(!Connected){
			if(InitCommand() != ERROR_SUCCESS) {
				goto Start;
			}
		}

		BYTE* TmpBuffer = (BYTE*)XEncryptedAlloc(DataLen+8);

		// Copy our id and len
		memcpy(TmpBuffer, &CommandId, sizeof(DWORD));
		memcpy(TmpBuffer + 4, &DataLen, sizeof(DWORD));

		// Encrypt and copy
		XeCryptRc4(RC4Key, 0x10, (BYTE*)CommandData, DataLen);

		memcpy(TmpBuffer + 8, CommandData, DataLen);

		// Send all our data
		DWORD bytesLeft = DataLen + 8;
		CHAR* curPos = (CHAR*)TmpBuffer;
		while(bytesLeft > 0) {
			DWORD sendSize = min(SEND_RECV_SIZE, bytesLeft);
			DWORD cbSent = NetDll_send(XNCALLER_SYSAPP, hSocket, curPos, sendSize, NULL);
			if(cbSent == SOCKET_ERROR) {
				LastError = WSAGetLastError();
				printf("SendCommand: send error %d", LastError);
				return E_FAIL;
			}
			bytesLeft -= cbSent;
			curPos += cbSent;
		}

		// All done
		return ERROR_SUCCESS;
	}

	HRESULT ReceiveData(VOID* Buffer, DWORD BytesExpected, BOOL breakOnZero) {

		// Make sure we are connected
		if(!Connected){ 
			printf("ReceiveData: not connected."); 
			return E_FAIL;
		}

		// Loop and recieve our data
		DWORD bytesLeft = BytesExpected;
		DWORD bytesRecieved = 0;
		while(bytesLeft > 0) {
			if(!Connected){ //DISCONNECT MID TRANSFER
				printf("ReceiveData: not connected."); 
				return E_FAIL;
			}
			DWORD recvSize = min(SEND_RECV_SIZE, bytesLeft);
			DWORD cbRecv = NetDll_recv(XNCALLER_SYSAPP, hSocket, (CHAR*)Buffer + bytesRecieved, recvSize, NULL);
			if(cbRecv == SOCKET_ERROR) {
				LastError = WSAGetLastError();
				printf("ReceiveData: recv error %d", LastError);
				return E_FAIL;
			}
			if(breakOnZero == TRUE && cbRecv == 0) { printf("ReceiveData: recv cbRecv = 0"); break; }
			bytesLeft -= cbRecv;
			bytesRecieved += cbRecv;
		}

		// Decrypt our data now
		if(bytesRecieved != BytesExpected) { printf("ReceiveData: size mismatch!"); return E_FAIL;}

		XeCryptRc4(RC4Key, 0x10, (BYTE*)Buffer, bytesRecieved);
		return ERROR_SUCCESS;
	}

	HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Responce, DWORD ResponceLength, BOOL KeepOpen) {
		CmdPending = TRUE;
		// Enter our lock
		EnterCriticalSection(&Critical);

		// First lets setup our net
		HRESULT returnValue = ERROR_SUCCESS;
		if(InitCommand() != ERROR_SUCCESS) {
			returnValue = E_FAIL;
			goto Finish;
		}

		// Now lets send off our command
		if(SendCommand(CommandId, CommandData, CommandLength) != ERROR_SUCCESS) {
			returnValue = E_FAIL;
			goto Finish;
		}

		// Now lets get our responce
		if(ReceiveData(Responce, ResponceLength, TRUE) != ERROR_SUCCESS) {
			returnValue = E_FAIL;
			goto Finish;
		}

		// Now end our command if we need to
		if(KeepOpen == FALSE) {
			EndCommand();
		}

		// All done, clean up and return
	Finish:
		CmdPending = FALSE;
		LeaveCriticalSection(&Critical);
		return returnValue;
	}

	VOID FailedConnect(){
		//Retry = TRUE;
		if (RetryAttempt >= 5){
			XNotifyQueueUI(XNOTIFYUI_TYPE_CONSOLEMESSAGE, 0, 2, L"LiquidSky - Couldn't Connect to Server!", 0);
			Sleep(5000);
			HalReturnToFirmware(HalResetSMCRoutine);
			return;
		}
		RetryAttempt++;
		wchar_t Buffer[100];
		swprintf(Buffer, L"LiquidSky - Attempting to connect to server!\nAttempt  %d of 5", RetryAttempt);
		XNotifyQueueUI(XNOTIFYUI_TYPE_CONSOLEMESSAGE, 0, 2, Buffer, 0);
		Sleep(5000);
	}
}

namespace Server {

	BYTE GotSalt = 0;

	tm* GetDifference(long long expire){
		time_t ftime = expire - time(NULL);
		return gmtime(&ftime);
	}

	VOID ShowTime(){
		wchar_t buffer[70];
		tm* time = GetDifference(Globals::UExpire);
		swprintf(buffer, L"Tampered Live - Time Remaining\n%d Days | %d Hours %d Minutes ", Globals::Days, time->tm_hour, time->tm_min);
	}

	VOID GetSecHeader(Sockets::SEC_HEADER* SecHeader){
		memcpy(SecHeader->CpuKey, Globals::CPUKey_Struct->realCpuKey, 0x10); //CPU
		SecHeader->Major = XEX_VERSION_MAJOR; //VER_MAJ
		SecHeader->Minor = XEX_VERSION_MINOR; //VER_MIN
		Utilities::MemoryBuffer MemBuffer; //XEX HASH
		PDWORD MemBuffer;
		if(Utilities::CReadFile(PATH_MODULE, MemBuffer) == TRUE) { 
			XeCryptHmacSha(Sockets::RC4Key, 16, MemBuffer.GetData(), MemBuffer.GetDataLength(), NULL, 0, NULL, 0, SecHeader->ExecutableHash, 16);
		}
		delete &MemBuffer;
		memcpy(SecHeader->Session, &Globals::Session, 0x8); //SESSION
	}

	VOID HandleCommand(WORD Command){
		if (Command == Sockets::CLI_CMD::DSHBRD){
			printf("dshboard \r\n");
		}

		else if (Command == Sockets::CLI_CMD::F_UPDATE){
			printf("f update \r\n");
		}

		else if (Command == Sockets::CLI_CMD::MSGBOX || Command == Sockets::CLI_CMD::XNOTIFY){
			printf("msg/xnotif \r\n");
			DoCommand(Command); //Get Messagebox/xnotify from server
		}

		else if (Command == Sockets::CLI_CMD::REBOOT){
			printf("reboot \r\n");
		}
	}

	VOID HandleStatus(WORD Status, WORD AuthType){
		if(Globals::LastStatus == Status && Globals::AuthType == AuthType) return; //Same Status return
		Globals::LastStatus = Status; //update status

		//Authed
		if(Status == Sockets::STATUS::AUTHED){
			if(Globals::AuthType != AuthType) DoSalt(); //Auth Changed get new auth data
			printf("new auth \r\n");
		}

		//not authed never connected
		else if(Status == Sockets::STATUS::NO_AUTH){
			printf("Not registered \r\n");
		}

		//Error occurred reboot
		else if(Status == Sockets::STATUS::ERROR){
			printf("error \r\n");
		}


		//blacklist notify and reboot
		else if(Status == Sockets::STATUS::BLACKLIST){
			printf("blacklist \r\n");
		}

		//expired but in db
		else if (Status == Sockets::STATUS::EXPIRED){
			printf("expired \r\n");
		}

		//tampered plugin reboot
		else if (Status == Sockets::STATUS::TAMPER){
			printf("tampered \r\n");
		}

		//update
		else if (Status == Sockets::STATUS::UPDATE_AVAIL){
			printf("update \r\n");
		}

		//big error
		else {
			printf("ERROR \r\n");
		}
	}

	HRESULT DoSalt(){
		
		//Get Sec Header
		Sockets::SEC_HEADER SecHeader;
		GetSecHeader(&SecHeader);

		//Fill in request
		Sockets::Requests::SALT* SaltRequest = (Sockets::Requests::SALT*)XEncryptedAlloc(sizeof(Sockets::Requests::SALT));
		memcpy(&SaltRequest->SecHeader, &SecHeader, sizeof(Sockets::SEC_HEADER));
		//kv
		HVPeekPoke::HvPeekBytes(HVPeekPoke::HvPeekQWORD(hvKvPtrRetail), SaltRequest->KV, 0x4000);

		//do command
		Sockets::Responses::SALT SaltResponse;
		if(Sockets::SendCommand(Sockets::CMD::GSALT, SaltRequest, sizeof(Sockets::Requests::SALT), &SaltResponse, sizeof(Sockets::Responses::SALT), TRUE) != ERROR_SUCCESS) {
			printf("DoSalt - Command Failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_AVOID_REVIEW, 0, 2, L"An Error Has Occurred.", 0);
			return E_FAIL;
		}

		XEncryptedFree(SaltRequest);
		Sockets::EndCommand();

		//store some client info
		memcpy(Globals::Session, SaltResponse.Session, 0x8);
		memcpy(Globals::Name, SaltResponse.Name, 20);
		Globals::Days = SaltResponse.Days;
		Globals::UExpire = SaltResponse.UnixExpire;
		Globals::AuthType = SaltResponse.AuthType;

		HandleStatus(SaltResponse.Status, SaltResponse.AuthType);

		if(GotSalt == 0) GotSalt = 1;
		return ERROR_SUCCESS;
	}

	HRESULT DoStatus(){

		//Get Sec Header
		Sockets::SEC_HEADER SecHeader;
		GetSecHeader(&SecHeader);

		//Fill in request
		Sockets::Requests::STATUS* StatusRequest = (Sockets::Requests::STATUS*)XEncryptedAlloc(sizeof(Sockets::Requests::STATUS));

		//Gamertag
		XUSER_SIGNIN_INFO userInfo; ZeroMemory(&userInfo, sizeof(XUSER_SIGNIN_INFO));
		if(XUserGetSigninInfo(0, XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, &userInfo) == ERROR_SUCCESS) {
			memcpy(StatusRequest->Gamertag, userInfo.szUserName, 16);
		}
		//secheader
		memcpy(&StatusRequest->SecHeader, &SecHeader, sizeof(Sockets::SEC_HEADER));
		//titleid
		StatusRequest->TitleID = XamGetCurrentTitleId();

		Sockets::Responses::STATUS StatusResponse;
		if(Sockets::SendCommand(Sockets::CMD::GSTATUS, StatusRequest, sizeof(Sockets::Requests::STATUS), &StatusResponse, sizeof(Sockets::Responses::STATUS), TRUE) != ERROR_SUCCESS) {
			printf("DoStatus - Command Failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_AVOID_REVIEW, 0, 2, L"An Error Has Occurred.", 0);
			return E_FAIL;
		}

		XEncryptedFree(StatusRequest);
		Sockets::EndCommand();

		HandleStatus(StatusResponse.Status, StatusResponse.AuthType);
		HandleCommand(StatusResponse.Command);

		return ERROR_SUCCESS;
	}

	HRESULT DoUpdate(){
		//UPDATE
		Sockets::UpdateInProgress = TRUE;

		//Get Sec Header
		Sockets::SEC_HEADER SecHeader;
		GetSecHeader(&SecHeader);

		//Do buffer
		Sockets::Requests::UPDATE* UpdateRequest = (Sockets::Requests::UPDATE*)XEncryptedAlloc(sizeof(Sockets::Requests::UPDATE));
		memcpy(&UpdateRequest->SecHeader, &SecHeader, sizeof(Sockets::Requests::UPDATE));

		Sockets::Responses::UPDATE UpdateResponse;
		if(Sockets::SendCommand(Sockets::CMD::UPDATE, UpdateRequest, sizeof(Sockets::Requests::UPDATE), &UpdateResponse, sizeof(Sockets::Responses::UPDATE), TRUE) != ERROR_SUCCESS) {
			Sockets::UpdateInProgress = FALSE;
			printf("ServerGetUpdate - Command Failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, 0, 2, L"LiquidSky- Update Failed!", 0);
			return E_FAIL;
		}

		XEncryptedFree(UpdateRequest);
		
		if(UpdateResponse.Length == 0){
			Sockets::UpdateInProgress = FALSE;
			printf("ServerGetUpdate - Module Size = 0");
			XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, 0, 2, L"LiquidSky- Update Failed!", 0);
			return E_FAIL;
		}

		DWORD Size = UpdateResponse.Length;
		BYTE* Buffer = (BYTE*)XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);

		//couldnt allocate
		if(Buffer == NULL) {
			Sockets::UpdateInProgress = FALSE;
			printf("ServerGetUpdate - Allocate Failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, 0, 2, L"LiquidSky- Update Failed!", 0);
			return E_FAIL;
		}

		// Now Recieve our data
		if(Sockets::ReceiveData(Buffer, Size, FALSE) != ERROR_SUCCESS) {
			Sockets::UpdateInProgress = FALSE;
			XPhysicalFree(Buffer);
			printf("ServerGetUpdate - Rcv Data Failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, 0, 2, L"LiquidSky- Update Failed!", 0);
			return E_FAIL;
		}

		if(Utilities::CWriteFile(PATH_MODULE, Buffer, Size) != TRUE) {
			Sockets::UpdateInProgress = FALSE;
			XPhysicalFree(Buffer);
			printf("ServerGetUpdate - CWriteFile failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_GENERIC, 0, 2, L"LiquidSky - Update Failed!", 0);
			return E_FAIL;
		}

		// Now lets clean up a little
		Sockets::EndCommand();
		XPhysicalFree(Buffer);
		printf("ServerGetUpdate - Update complete, rebooting");
		Sleep(3000);
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		// We shouldn't get here because of the reboot
		return ERROR_SUCCESS;

	}

	HRESULT DoCommand(WORD Command){
		//Get Sec Header
		Sockets::SEC_HEADER SecHeader;
		GetSecHeader(&SecHeader);

		//Fill in request
		Sockets::Requests::CMD* CommandRequest = (Sockets::Requests::CMD*)XEncryptedAlloc(sizeof(Sockets::Requests::CMD));
		//secheader
		memcpy(&CommandRequest->SecHeader, &SecHeader, sizeof(Sockets::SEC_HEADER));

		Sockets::Responses::CMD CommandResponse;
		if(SendCommand(Sockets::CMD::RCV_CMD, &CommandRequest, sizeof(Sockets::Requests::CMD), &CommandResponse, sizeof(Sockets::Responses::CMD), FALSE) != ERROR_SUCCESS){
			printf("DoCommand - RCV Command Failed");
			XNotifyQueueUI(XNOTIFYUI_TYPE_AVOID_REVIEW, 0, 2, L"An Error Has Occurred.", 0);
			return E_FAIL;
		}

		XEncryptedFree(CommandRequest);
		Sockets::EndCommand();

		if(Command == Sockets::CLI_CMD::MSGBOX){
			//do messageboxui
		} else if (Command == Sockets::CLI_CMD::XNOTIFY){
			//do xnotify
		} else {
			//error
			return E_FAIL;
		}

		return ERROR_SUCCESS;

	}

	VOID DoServerTick(){
		while(DoSalt() != ERROR_SUCCESS){
			Sleep(1000);
		}

		while(TRUE){
			DoStatus();
			Sleep(30000); //30 Second Wait time
		}
	}
}