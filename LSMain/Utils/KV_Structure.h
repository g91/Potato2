#include "stdafx.h"

namespace KV_Structure {
#pragma pack(1)
	typedef enum _ODD_POLICY {
    ODD_POLICY_FLAG_CHECK_FIRMWARE = 0x120,
  } ODD_POLICY;

  typedef union _INQUIRY_DATA {
    struct {
      BYTE DeviceType : 5;
      BYTE DeviceTypeQualifier : 3;
      BYTE DeviceTypeModifier : 7;
      BYTE RemovableMedia : 1;
      BYTE Versions : 8;
      BYTE ResponseDataFormat : 4;
      BYTE HiSupport : 1;
      BYTE NormACA : 1;
      BYTE ReservedBit : 1;
      BYTE AERC : 1;
      BYTE AdditionalLength : 8;
      WORD Reserved : 16;
      BYTE SoftReset : 1;
      BYTE CommandQueue : 1;
      BYTE Reserved2 : 1;
      BYTE LinkedCommands : 1;
      BYTE Synchronous : 1;
      BYTE Wide16Bit : 1;
      BYTE Wide32Bit : 1;
      BYTE RelativeAddressing : 1;
      BYTE VendorId[8];
      BYTE ProductId[16];
      BYTE ProductRevisionLevel[4];
    };
    BYTE Data[0x24];
  } INQUIRY_DATA, *pINQUIRY_DATA;
  C_ASSERT(sizeof(INQUIRY_DATA) == 0x24);

  typedef struct _XEIKA_ODD_DATA {
    BYTE         Version;
    BYTE         PhaseLevel;
    INQUIRY_DATA InquiryData;
  } XEIKA_ODD_DATA, *PXEIKA_ODD_DATA;
  C_ASSERT(sizeof(XEIKA_ODD_DATA) == 0x26);


  typedef struct _XEIKA_DATA {
    XECRYPT_RSAPUB_2048 PublicKey;
    DWORD               Signature;
    WORD                Version;
    XEIKA_ODD_DATA      OddData;
    BYTE                Padding[4];
  } XEIKA_DATA, *PXEIKA_DATA;
  C_ASSERT(sizeof(XEIKA_DATA) == 0x140);

  typedef struct _XEIKA_CERTIFICATE {
    WORD       Size;
    XEIKA_DATA Data;
    BYTE       Padding[0x1146];
  } XEIKA_CERTIFICATE, *PXEIKA_CERTIFICATE;
  C_ASSERT(sizeof(XEIKA_CERTIFICATE) == 0x1288);

  typedef struct _KEY_VAULT {                   // Key #
    BYTE  HmacShaDigest[0x10];                  //            0x0000
    BYTE  Confounder[0x08];                     //            0x0010
    BYTE  ManufacturingMode;                    // 0x00       0x0018
    BYTE  AlternateKeyVault;                    // 0x01       0x0019
    BYTE  RestrictedPrivilegesFlags;            // 0x02       0x001A
    BYTE  ReservedByte3;                        // 0x03       0x001B
    WORD  OddFeatures;                          // 0x04       0x001C
    WORD  OddAuthtype;                          // 0x05       0x001E
    DWORD RestrictedHvextLoader;                // 0x06       0x0020
    DWORD PolicyFlashSize;                      // 0x07       0x0024
    DWORD PolicyBuiltinUsbmuSize;               // 0x08       0x0028
    DWORD ReservedDword4;                       // 0x09       0x002C
    QWORD RestrictedPrivileges;                 // 0x0A       0x0030
    QWORD ReservedQword2;                       // 0x0B       0x0038
    QWORD ReservedQword3;                       // 0x0C       0x0040
    QWORD ReservedQword4;                       // 0x0D       0x0048
    BYTE  ReservedKey1[0x10];                   // 0x0E       0x0050
    BYTE  ReservedKey2[0x10];                   // 0x0F       0x0060
    BYTE  ReservedKey3[0x10];                   // 0x10       0x0070
    BYTE  ReservedKey4[0x10];                   // 0x11       0x0080
    BYTE  ReservedRandomKey1[0x10];             // 0x12       0x0090
    BYTE  ReservedRandomKey2[0x10];             // 0x13       0x00A0
    BYTE  ConsoleSerialNumber[0xC];             // 0x14       0x00B0
    BYTE  MoboSerialNumber[0xC];                // 0x15       0x00BC
    WORD  GameRegion;                           // 0x16       0x00C8
    BYTE  Padding1[0x6];                        //            0x00CA
    BYTE  ConsoleObfuscationKey[0x10];          // 0x17       0x00D0
    BYTE  KeyObfuscationKey[0x10];              // 0x18       0x00E0
    BYTE  RoamableObfuscationKey[0x10];         // 0x19       0x00F0
    BYTE  DvdKey[0x10];                         // 0x1A       0x0100
    BYTE  PrimaryActivationKey[0x18];           // 0x1B       0x0110
    BYTE  SecondaryActivationKey[0x10];         // 0x1C       0x0128
    BYTE  GlobalDevice2desKey1[0x10];           // 0x1D       0x0138
    BYTE  GlobalDevice2desKey2[0x10];           // 0x1E       0x0148
    BYTE  WirelessControllerMs2desKey1[0x10];   // 0x1F       0x0158
    BYTE  WirelessControllerMs2desKey2[0x10];   // 0x20       0x0168
    BYTE  WiredWebcamMs2desKey1[0x10];          // 0x21       0x0178
    BYTE  WiredWebcamMs2desKey2[0x10];          // 0x22       0x0188
    BYTE  WiredControllerMs2desKey1[0x10];      // 0x23       0x0198
    BYTE  WiredControllerMs2desKey2[0x10];      // 0x24       0x01A8
    BYTE  MemoryUnitMs2desKey1[0x10];           // 0x25       0x01B8
    BYTE  MemoryUnitMs2desKey2[0x10];           // 0x26       0x01C8
    BYTE  OtherXsm3DeviceMs2desKey1[0x10];      // 0x27       0x01D8
    BYTE  OtherXsm3DeviceMs2desKey2[0x10];      // 0x28       0x01E8
    BYTE  WirelessController3p2desKey1[0x10];   // 0x29       0x01F8
    BYTE  WirelessController3p2desKey2[0x10];   // 0x2A       0x0208
    BYTE  WiredWebcam3p2desKey1[0x10];          // 0x2B       0x0218
    BYTE  WiredWebcam3p2desKey2[0x10];          // 0x2C       0x0228
    BYTE  WiredController3p2desKey1[0x10];      // 0x2D       0x0238
    BYTE  WiredController3p2desKey2[0x10];      // 0x2E       0x0248
    BYTE  MemoryUnit3p2desKey1[0x10];           // 0x2F       0x0258
    BYTE  MemoryUnit3p2desKey2[0x10];           // 0x30       0x0268
    BYTE  OtherXsm3Device3p2desKey1[0x10];      // 0x31       0x0278
    BYTE  OtherXsm3Device3p2desKey2[0x10];      // 0x32       0x0288
    XECRYPT_RSAPRV_1024 ConsolePrivateKey;      // 0x33       0x0298
    XECRYPT_RSAPRV_2048 XeikaPrivateKey;        // 0x34       0x0468
    XECRYPT_RSAPRV_1024 CardeaPrivateKey;       // 0x35       0x07F8
    XE_CONSOLE_CERTIFICATE ConsoleCertificate;  // 0x36       0x09C8
    XEIKA_CERTIFICATE XeikaCertificate;         // 0x37       0x0B70
    BYTE  KeyVaultSignature[0x100];             // 0x44       0x1DF8
    BYTE  CardeaCertificate[0x2108];            // 0x38       0x1EF8
  } KEY_VAULT, *PKEY_VAULT;                                   //0x4000
  C_ASSERT(sizeof(KEY_VAULT) == 0x4000);

#pragma pack()
}