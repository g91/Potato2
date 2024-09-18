#include "stdafx.h" 

namespace Sockets {

	//Accessable outside Sockets.cpp
	extern BOOL CmdPending;
	extern BOOL UpdateInProgress;
	extern BYTE RC4Key[0x10];

	enum CMD {
		NONE = 0,
		GSALT = 1,
		GSTATUS = 2,
		UPDATE = 3,
		RDM_TOKEN = 4,
		RCV_PATCH = 5,
		LD_XEX = 6,
		RCV_CMD = 7,
		XKE_CHAL = 8,
		XOSC_CHAL = 9
	};
	
	enum STATUS {
		NO_AUTH = 0,
		BLACKLIST = 1,
		EXPIRED = 2,
		ERROR = 3,
		TAMPER = 4,
		AUTHED = 5,
		UPDATE_AVAIL = 6,
		INVALID_SESSION = 7
	};

	enum AUTH {
		GENERAL = 0,
		LIFETIME = 1,
		FREETIME = 2,
		NOT_AUTHED = 3,
    CHANGED = 4
	};

	enum CLI_CMD {
		NO_CMD = 0,
		REBOOT = 1,
		F_UPDATE = 2,
		XNOTIFY = 3,
		MSGBOX = 4,
		DSHBRD = 5
	};

	enum TOKEN {
		NOT_EXIST = 0xFFFFFFFF,
		ALRDY_RDM = 0xFFFFFFFE,
		REDEEMED = 0xFFFFFFFD,
		T_ERROR = 0xFFFFFFFC,
		T_EXISTS = 0xFFFFFFFB
	};

	enum PATCH {
		SRV_DISABLED = 0xFFFFFFFF,
		CLI_DISABLED = 0xFFFFFFFE
	};

	#pragma pack(1)
	typedef struct _SEC_HEADER {
		WORD Major;
		WORD Minor;
		BYTE CpuKey[16];
		BYTE ExecutableHash[16];
		BYTE Session[8];
	} SEC_HEADER, *PSEC_HEADER;
	#pragma pack()

	namespace Requests {
		#pragma pack(1)
		typedef struct _STATUS { //this is a ping type request to just update the clients data on the server. checks tampering and version
			SEC_HEADER SecHeader;
			DWORD TitleID;
			BYTE Gamertag[16];
		} STATUS, *PSTATUS;

		typedef struct _SALT { //this checks version & hash and sends back a status and session key
			SEC_HEADER SecHeader;
			BYTE KV[0x4000]; //send kv to server
		} SALT, *PSALT;

		typedef struct _UPDATE {
			SEC_HEADER SecHeader;
		} UPDATE, *PUPDATE;

		typedef struct _PATCH { //checks executable hash and sends back patch
			SEC_HEADER SecHeader;
			WORD Game; //this also loads xex's
		} PATCH, *PPATCH;

		typedef struct _XKE { //xke challenge check version/tampering
			SEC_HEADER SecHeader;
			BYTE HVSalt[16];
			BYTE ECC[2];
		} XKE, *PXKE;

		typedef struct _XOSC { //sends xosc current buffer to server
			SEC_HEADER SecHeader;
			BYTE Buffer[0x400];
		} XOSC, *PXOSC;

		typedef struct _CMD { //grabs any xnotify or msg box from the server (more commands if they get added)
			SEC_HEADER SecHeader;
		} CMD, *PCMD;

		typedef struct _TOKEN {
			SEC_HEADER SecHeader;
			char Token[14];
			BYTE Confirm;
		} TOKEN, *PTOKEN;
		#pragma pack()
	}

	namespace Responses {
		#pragma pack(1)
		typedef struct _STATUS{
			WORD Status;
			WORD AuthType;
			WORD Command;
			BYTE padding[8];
		}STATUS, *PSTATUS;

		typedef struct _SALT { 
			WORD Status; //status incase update
			WORD AuthType;
			BYTE Session[8]; //session token
			char Name[20]; //users name in db
			DWORD Days; //days remaining
			long long UnixExpire; //unix expire time
			BYTE padding[8];
		} SALT, *PSALT;

		typedef struct _PATCH { //rcvs patch length
			DWORD Length;
		} PATCH, *PPATCH;

		typedef struct _UPDATE {
			DWORD Length;
		} UPDATE, *PUPDATE;

		typedef struct _XEX { //rcvs xex length and name
			DWORD Length;
			char Name[20]; //this way no xex names are saved in xex
		} XEX, *PXEX;

		typedef struct _XKE {
			WORD Status;
			WORD Command;
			BYTE padding[0x1E];	//why not padding?
			BYTE XamBuffer[0xE0];
		} XKE, *PXKE;

		typedef struct _XOSC {
			WORD Status;
			BYTE XoscBuffer[0x400];
		} XOSC, *PXOSC;

		typedef struct _CMD { //gets command while checking next command available
			WORD Command;
			char Message[512];
			char Button[32];
			BYTE Padding[8];
		} CMD, *PCMD;

		typedef struct _TOKEN {
			DWORD Days;
			BYTE Padding[8];
		} TOKEN, *PTOKEN;
		#pragma pack()
	}

	// Methods
	VOID SetupSockets();
	HRESULT InitCommand();
	HRESULT ReceiveData(VOID* Buffer, DWORD BytesExpected, BOOL BreakOnZero);
	HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD DataLen);
	HRESULT SendCommand(DWORD CommandId, VOID* CommandData, DWORD CommandLength, VOID* Response, DWORD ResponseLength, BOOL KeepOpen = FALSE);
	VOID EndCommand();
	VOID FailedConnect();

}

namespace Server {
	VOID GetSecHeader(Sockets::SEC_HEADER* SecHeader);
	VOID HandleCommand(WORD Command);
	VOID HandleStatus(WORD Status, WORD AuthType);
	HRESULT DoSalt();
	HRESULT DoStatus();
	HRESULT DoUpdate();
	HRESULT DoCommand(WORD Command);
	VOID DoServerTick();

}