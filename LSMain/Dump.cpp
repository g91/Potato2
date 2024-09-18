#include "stdafx.h"
#include "Dump.h"

namespace dump
{
	unsigned char hvPayload[112] = {
		0x3D, 0x60, 0x00, 0x01, 0x48, 0x00, 0x00, 0x05,
		0x7C, 0x68, 0x02, 0xA6, 0x38, 0x63, 0x00, 0x38,
		0xE8, 0x83, 0x00, 0x09, 0x2C, 0x24, 0xFF, 0xFF,
		0x41, 0x82, 0x00, 0x20, 0x7D, 0x69, 0x03, 0xA6,
		0x89, 0x24, 0x00, 0x00, 0x99, 0x28, 0x00, 0x00,
		0x38, 0x84, 0x00, 0x01, 0x39, 0x08, 0x00, 0x01,
		0x42, 0x00, 0xFF, 0xF0, 0x4B, 0xFF, 0xFF, 0xDC,
		0x38, 0x21, 0x00, 0x10, 0x60, 0x00, 0x00, 0x00,
		0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20,
		0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00,
		0x80, 0x00, 0x01, 0x04, 0x00, 0x02, 0x00, 0x00,
		0x80, 0x00, 0x01, 0x06, 0x00, 0x03, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	unsigned char hvPayload_tst[112] = {
		0x3D, 0x60, 0x00, 0x01, 0x48, 0x00, 0x00, 0x05,
		0x7C, 0x68, 0x02, 0xA6, 0x38, 0x63, 0x00, 0x38,
		0xE8, 0x83, 0x00, 0x09, 0x2C, 0x24, 0xFF, 0xFF,
		0x41, 0x82, 0x00, 0x20, 0x7D, 0x69, 0x03, 0xA6,
		0x89, 0x24, 0x00, 0x00, 0x99, 0x28, 0x00, 0x00,
		0x38, 0x84, 0x00, 0x01, 0x39, 0x08, 0x00, 0x01,
		0x42, 0x00, 0xFF, 0xF0, 0x4B, 0xFF, 0xFF, 0xDC,
		0x38, 0x21, 0x00, 0x10, 0x60, 0x00, 0x00, 0x00,
		0x7D, 0x88, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20,
		0x80, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x80, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x80, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x80, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	BYTE hvPayload_2bl[84] = {
		0x3D, 0x60, 0x00, 0x01, 0x48, 0x00, 0x00, 0x05,
		0x7C, 0x68, 0x02, 0xA6, 0x38, 0x63, 0x00, 0x30,
		0xE8, 0x83, 0x00, 0x09, 0x2C, 0x24, 0xFF, 0xFF,
		0x41, 0x82, 0x00, 0x1C, 0x7D, 0x69, 0x03, 0xA6,
		0x89, 0x24, 0x00, 0x00, 0x99, 0x28, 0x00, 0x00,
		0x38, 0x84, 0x00, 0x01, 0x39, 0x08, 0x00, 0x01,
		0x42, 0x00, 0xFF, 0xF0, 0x38, 0x21, 0x00, 0x10,
		0x60, 0x00, 0x00, 0x00, 0x7D, 0x88, 0x03, 0xA6,
		0x4E, 0x80, 0x00, 0x20, 0x80, 0x00, 0x02, 0x00,
		0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF
	};

	unsigned char XeCrypt_r31[0x20] = {
		0x3D, 0x80, 0x80, 0x00, 0x61, 0x8C, 0x01, 0x06,
		0x79, 0x8C, 0x07, 0xC6, 0x3D, 0x8C, 0x00, 0x03,
		0x61, 0x8C, 0x26, 0x00, 0xFB, 0xEC, 0x00, 0x00,
		0x39, 0x60, 0x02, 0x18, 0x4B, 0xFF, 0x51, 0x48
	};

	unsigned char XeCrypt_data[0x50] = {
		0x3D, 0x80, 0x80, 0x00, 0x61, 0x8C, 0x01, 0x06,
		0x79, 0x8C, 0x07, 0xC6, 0x3D, 0x8C, 0x00, 0x03,
		0x61, 0x8C, 0x26, 0x00, 0xE9, 0x6C, 0x00, 0x00,
		0x28, 0x2B, 0x00, 0x00, 0x40, 0x82, 0x00, 0x08,
		0x7D, 0x8B, 0x63, 0x78, 0x7C, 0x89, 0x23, 0x78,
		0x7C, 0xA9, 0x03, 0xA6, 0x89, 0x09, 0x00, 0x00,
		0x99, 0x0B, 0x00, 0x08, 0x39, 0x6B, 0x00, 0x01,
		0x42, 0x00, 0xFF, 0xF4, 0xF8, 0x8B, 0x00, 0x08,
		0x39, 0x6B, 0x00, 0x08, 0xF9, 0x6C, 0x00, 0x00,
		0x39, 0x60, 0x02, 0x18, 0x4B, 0xFF, 0x51, 0x00
	}; // 3D808000618C0106798C07C63D8C0003618C2600E96C0000282B0000408200087D8B63787C8923787CA903A689090000990B0008396B00014200FFF4F88B0008396B0008F96C0000396002184BFF5100

	// Dumps the offsets sent to XeCryptShaUpdate to 0x32600
	unsigned char XeCrypt_offsets[0x30] = {
		0x3D, 0x80, 0x80, 0x00, 0x61, 0x8C, 0x01, 0x06,
		0x79, 0x8C, 0x07, 0xC6, 0x3D, 0x8C, 0x00, 0x03,
		0x61, 0x8C, 0x26, 0x00, 0xE9, 0x6C, 0x00, 0x00,
		0x7D, 0x8B, 0x5B, 0x78, 0xF8, 0x8B, 0x00, 0x08,
		0x39, 0x6B, 0x00, 0x08, 0xF9, 0x6C, 0x00, 0x00,
		0x39, 0x60, 0x02, 0x18, 0x4B, 0xFF, 0x51, 0x38
	};

	unsigned char XeCrypt_size[0x30] = {
		0x3D, 0x80, 0x80, 0x00, 0x61, 0x8C, 0x01, 0x06,
		0x79, 0x8C, 0x07, 0xC6, 0x3D, 0x8C, 0x00, 0x03,
		0x61, 0x8C, 0x26, 0x00, 0xE9, 0x6C, 0x00, 0x00,
		0x7D, 0x8B, 0x5B, 0x78, 0xF8, 0xAB, 0x00, 0x08,
		0x39, 0x6B, 0x00, 0x08, 0xF9, 0x6C, 0x00, 0x00,
		0x39, 0x60, 0x02, 0x18, 0x4B, 0xFF, 0x51, 0x38
	};

	unsigned char MyAddy[4] = {
		0x00, 0x00, 0xB6, 0x18
	};

	void HvxPeekBytes(ULONGLONG Address, LPVOID buf, DWORD length) {
		BYTE * data = (BYTE*)XPhysicalAlloc(length, MAXULONG_PTR, NULL, PAGE_READWRITE); //make sure to free this memory when you are done with it!
		__int64 addr = 0x8000000000000000ULL + (DWORD)MmGetPhysicalAddress((DWORD*)data);
		Hvx::HvGetVersion(0x72627472, 5, Address, addr, length, 0LL);
		memcpy(buf, data, length);
		XPhysicalFree(data);
	}

	void DumpHv()
	{
		DbgOut("Dumping HV....\n");
		PBYTE pbHvBuf = (PBYTE)XPhysicalAllocM(0x40000);
		ZeroMemory(pbHvBuf, 0x40000);

		QWORD pqwAddress = 0;
		QWORD rtoc = 0x0000000200000000;
		DWORD dwPageSize = 0x10000;
		for (int i = 0; i < 4; i++)
		{
			printf("Reading page %d (0x%016llX)...\n", i, pqwAddress);
			Hvx::HvPeekBytes(pqwAddress, pbHvBuf+(i*dwPageSize), dwPageSize);
			pqwAddress += (rtoc + dwPageSize);
		}

		printf("Saving...\n");
		//if (!CWriteFile(va("Hdd:\\XeKeys\\HV_dump_%s.bin", getTime().c_str()).c_str(), pbHvBuf, 0x40000))
		if (!CWriteFile(va("Hdd:\\XeKeys\\HV_dump_17511.bin").c_str(), pbHvBuf, 0x40000))
			printf("Failed to write HV file\n");

		XPhysicalFree(pbHvBuf);
		printf("Done\n");
	}

	QWORD getFuseline(DWORD fuse)
	{
		if ((fuse * 0x40) < 0x300)
			return Hvx::HvPeekQWORD(0x8000020000020000ULL + ((fuse * 0x40) << 3));
		return 0;
	}

	void getCPUKey(BYTE* KeyBuf)
	{
		QWORD Key1 = getFuseline(3) | getFuseline(4);
		QWORD Key2 = getFuseline(5) | getFuseline(6);

		memcpy(KeyBuf, &Key1, 8);
		memcpy(KeyBuf + 8, &Key2, 8);
	}

	void DumpFuses()
	{
		QWORD fuseloc = 0x8000020000020000ULL;
		QWORD fuses[12] = { 0 };

		printf("Fuse Device:\n");
		for (int i = 0; i < 4; i++)
		{
			QWORD tmp = Hvx::HvPeekQWORD(fuseloc + 0x2000 + (i * 8));
			printf("[%02X]: %016llX\n", i * 8, tmp);
		}

		printf("Fuses:\n");
		for (int i = 0; i < 12; i++)
		{
			QWORD fuseAddress = 0x8000020000020000ULL + ((i * 0x40) << 3);
			fuses[i] = getFuseline(i);
			printf("Fuse [%02d][%016llX]: %016llX\n", i, fuseAddress, fuses[i]);
		}
	}

	void getCB_AKey(PBYTE Keybuf)
	{
		QWORD cbAddy = SPACE_NAND + Hvx::HvPeekDWORD(SPACE_NAND + 8);
		BYTE cbSalt[0x10];
		Hvx::HvPeekBytes(cbAddy+0x10, cbSalt, 0x10);
		XeCryptHmacSha(Keys::BLKey, 0x10, cbSalt, 0x10, 0, 0, 0, 0, Keybuf, 0x10);
	}

	void getCB_BKey(PBYTE Keybuf)
	{
		DWORD cbOffs = Hvx::HvPeekDWORD(SPACE_NAND + 8);
		DWORD cbbOffs = cbOffs + (Hvx::HvPeekDWORD(SPACE_NAND + cbOffs + 0xC) + 0xF) & 0xFFFFFFF0;
		QWORD cbbAddy = SPACE_NAND + cbbOffs;

		BYTE cbbSalt[0x10];
		BYTE cbKey[0x10];
		BYTE CPUKey[0x10];
		getCB_AKey(cbKey);
		getCPUKey(CPUKey);
		Hvx::HvPeekBytes(cbbAddy+0x10, cbbSalt, 0x10);
		XeCryptHmacSha(cbKey, 0x10, cbbSalt, 0x10, CPUKey, 0x10, 0, 0, Keybuf, 0x10);
	}

	void DumpCB_A()
	{
		DbgOut("Dumping CB_A....\n");
		QWORD cbAddy = SPACE_NAND + Hvx::HvPeekDWORD(SPACE_NAND + 8);
		DWORD size = Hvx::HvPeekDWORD(cbAddy+0xC);
		printf("cbAddy: %016llX\nSize: %X\n", cbAddy, size);
		PBYTE cb = (PBYTE)XPhysicalAlloc(size, MAXULONG_PTR, NULL, PAGE_READWRITE);
		Hvx::HvPeekBytes(cbAddy, cb, size);
		CWriteFile("Hdd:\\XeKeys\\cb_enc.bin", cb, size);

		BYTE rc4key[0x10];
		getCB_AKey(rc4key);
		XECRYPT_RC4_STATE rc4;
		XeCryptRc4Key(&rc4, rc4key, 0x10);
		XeCryptRc4Ecb(&rc4, cb + 0x20, size - 0x20);
		CWriteFile("Hdd:\\XeKeys\\cb_dec.bin", cb, size);
		XPhysicalFree(cb);
	}

	void DumpCB_B()
	{
		DbgOut("Dumping CB_B....\n");
		DWORD cbOffs = Hvx::HvPeekDWORD(SPACE_NAND + 8);
		DWORD cbbOffs = cbOffs + (Hvx::HvPeekDWORD(SPACE_NAND + cbOffs+0xC) + 0xF) & 0xFFFFFFF0;
		QWORD cbbAddy = SPACE_NAND + cbbOffs;
		DWORD size = Hvx::HvPeekDWORD(cbbAddy + 0xC);
		printf("cbbOffs: 0x%08X\ncbbAddy: 0x%016llX\nSize: 0x%X\n", cbbOffs, cbbAddy, size);
		PBYTE cbb = (PBYTE)XPhysicalAlloc(size, MAXULONG_PTR, NULL, PAGE_READWRITE);
		Hvx::HvPeekBytes(cbbAddy, cbb, size);
		CWriteFile("Hdd:\\XeKeys\\cbb_enc.bin", cbb, size);

		BYTE cbbKey[0x10];
		getCB_BKey(cbbKey);
		XECRYPT_RC4_STATE rc4;
		XeCryptRc4Key(&rc4, cbbKey, 0x10);
		XeCryptRc4Ecb(&rc4, cbb + 0x20, size - 0x20);
		CWriteFile("Hdd:\\XeKeys\\cbb_dec.bin", cbb, size);
		XPhysicalFree(cbb);
	}

	// dumps data checked by the challenge
	void DumpFirstHashData(LPCSTR filename)
	{
		BYTE *pHashDataTmp = (BYTE*)XPhysicalAlloc(0x1000, MAXULONG_PTR, NULL, PAGE_READWRITE);
		int idx = 0;
		// 0xEC hash info
		QWORD zAddy[7] = {
			0x340040,
			0x78FF88,
			0x2000100C00040,
			0x2000103505DF0,
			0x200016D2092E0,
			0x400020000FFFC,
			0x600030000FFFC
		};

		for (int i = 0; i < 7; i++)
		{
			Hvx::HvPeekBytes(zAddy[i] >> 16, pHashDataTmp + idx, zAddy[i] & 0xFFF);
			idx + zAddy[i] & 0xFFF;
		}

		CWriteFile(filename, pHashDataTmp, idx);
		XPhysicalFree(pHashDataTmp);
	}

	void DumpSecondHashData(LPCSTR filename)
	{
		BYTE *pHashDataTmp = (BYTE*)XPhysicalAlloc(0x1000, MAXULONG_PTR, NULL, PAGE_READWRITE);
		int idx = 0;

		// 0x50 hash info
		QWORD xAddy[0xD] = {
			0x34000C,
			0x400030,
			0x700004,
			0x780008,
			0x8081FF,
			0x2000100C00040,
			0x2000103500030,
			0x20001038080BB,
			0x2000161000040,
			0x200016D200060,
			0x200016D808125,
			0x4000200008200,
			0x6000300008200
		};

		for (int i = 0; i < 0xD; i++)
		{
			// if flag 0x8000 is set, it hashes cachelines, otherwise it hashes the HV
			if (xAddy[i] & 0x8000)
			{
				//FillCacheLines(xAddy[i] >> 16, xAddy[i] & 0x3FF);
				Hvx::HvPeekBytes(SPACE_SRAM + ((xAddy[i] >> 22) & 0xFFF), pHashDataTmp+idx, (xAddy[i] & 0x3FF) << 1);
				idx += (xAddy[i] & 0x3FF) << 1;
			}
			else
			{
				//FillCacheLines(xAddy[i] >> 16, 1);
				if ((xAddy[i] & 0x7F) >= 0x10)
					Hvx::HvPeekBytes((((xAddy[i] >> 16) & 0x3FFFF) | 0x8000000000000000), pHashDataTmp+idx, xAddy[i] & 0x7F);
				else
					Hvx::HvPeekBytes(xAddy[i] >> 16, pHashDataTmp+idx, xAddy[i] & 0x7F);
				idx += xAddy[i] & 0x7F;
			}
		}

		CWriteFile(filename, pHashDataTmp, idx);
		XPhysicalFree(pHashDataTmp);
	}

	void DumpData(LPCSTR filename)
	{
		DbgOut("Dumping HV Data...\n");
		DumpFirstHashData("Hdd:\\XeKeys\\EC.bin");
		DumpSecondHashData("Hdd:\\XeKeys\\EC.bin");
	}

	// Dumps the 0x8000020000010000 block - seems to follow the xbox memory encryption rules, seems encrypted but encryption changes each boot, this should be the 2bl location
	void DumpCache()
	{
		std::string time = getTime();
		printf("Dumping SoC Keys...\n");
		PQWORD pqwSocKeys = (PQWORD)XPhysicalAllocM(0x30);
		ZeroMemory(pqwSocKeys, 0x30);
		Hvx::HvPeekBytes(0x200010100, pqwSocKeys, 0x30);
		CWriteFile(va("Hdd:\\XeKeys\\Hvx_SoCKeys_%s.bin", time.c_str()).c_str(), pqwSocKeys, 0x30);
		XPhysicalFree(pqwSocKeys);

		printf("Dumping cache area...\n");
		QWORD addy = 0x8000020000010000ULL;
		printf("Dumping 0x%016llX... ", addy);
		BYTE *pHashDataTmp = (BYTE*)XPhysicalAlloc(0x10000, MAXULONG_PTR, NULL, PAGE_READWRITE);
		HvxPeekBytes(addy, pHashDataTmp, 0x10000);
		CWriteFile(va("Hdd:\\XeKeys\\Hvx_8000020000010000_%s.bin", time.c_str()).c_str(), pHashDataTmp, 0x10000);
		XPhysicalFree(pHashDataTmp);
		printf("Done!\n");
	}

	bool DumpArea(QWORD address, DWORD size, LPCSTR filename)
	{
		DbgOut("DumpArea: Address: 0x%016llX\tSize: 0x%X\tFilename: %s\n", address, size, filename);
		BYTE *pAreaDataTmp = (BYTE*)XPhysicalAlloc(size, MAXULONG_PTR, NULL, PAGE_READWRITE);
		Hvx::HvPeekBytes(address, pAreaDataTmp, size);
		bool ret = CWriteFile(filename, pAreaDataTmp, size);
		XPhysicalFree(pAreaDataTmp);
		return ret;
	}

	void DumpXexModule(char* modName)
	{
		HANDLE mHandle = NULL;
		printf("Getting Info For %s...\n", modName);
		NTSTATUS ret = XexGetModuleHandle(modName, &mHandle);
		if (ret != 0)
		{
			printf("BAD RETURN\n");
			return;
		}
		if (mHandle == NULL)
		{
			printf("BAD HANDLE\n");
			return;
		}
		PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY)mHandle;

		// take care of the annoying unicode strings
		char oName[128], iName[128];
		wcstombs(oName, data->BaseDllName.Buffer, data->BaseDllName.Length);
		wcstombs(iName, data->FullDllName.Buffer, data->FullDllName.Length);
		oName[data->BaseDllName.Length] = 0;
		iName[data->FullDllName.Length] = 0;

		// gather info
		printf("Original Name: %s\n", oName);
		printf("Full Name: %s\n", iName);
		printf("Original Base: 0x%08X\n", data->DllBaseOriginal);
		printf("Image Base: 0x%08X\n", data->ImageBase);
		printf("Entry point: 0x%08X\n", data->EntryPoint);
		printf("Image Base Phys: 0x%016X\n", MmGetPhysicalAddress(data->ImageBase));
		printf("Size of NT Image: %d\n", data->SizeOfNtImage);
		printf("Size of Full Image: %d\n", data->SizeOfFullImage);
		if (MmIsAddressValid(data->ImageBase))
			CWriteFile(va("Hdd:\\XeKeys\\%s_dumped.bin", oName).c_str(), data->ImageBase, data->SizeOfFullImage);
		else printf("Address 0x%08X is invalid!\n", data->ImageBase);

		// DO NOT DUMP BY PHYSICAL ADDRESS. DOES NOT WORK AT THE MOMENT
		//dump::DumpArea(MmGetPhysicalAddress(data->ImageBase), data->SizeOfFullImage, va("Hdd:\\XeKeys\\%s_dumped.bin", oName).c_str());
	}

	void DumpExpansion(int dwExpansion)
	{
		printf("Getting table address...\n");

		// subject to change on future dashboards
		QWORD pqwExpansionTblAddPointer = 0x200016958;

		// should work no matter the dashboard
		QWORD pqwExpansionTblAdd = Hvx::HvPeekQWORD(pqwExpansionTblAddPointer);
		pqwExpansionTblAdd += 0x400;
		printf("Table Address: %016llX\n", pqwExpansionTblAdd);
		for (int i = 0; i < 4; i++)
		{
			BYTE pbExpansionEntry[0x20];
			Hvx::HvPeekBytes(pqwExpansionTblAdd, pbExpansionEntry, 0x10);
			DWORD dwExpID = (*(DWORD*)pbExpansionEntry);
			printf("[%d] dwExpID: %08X\n", i, dwExpID);

			if (dwExpID == dwExpansion || dwExpansion == -1 || dwExpansion == i)
			{
				QWORD pqwExpHdrAdd = (*(QWORD*)(pbExpansionEntry + 8));
				printf("pqwExpHdrAdd: %016llX\n", pqwExpHdrAdd);
				Hvx::HvPeekBytes(pqwExpHdrAdd, pbExpansionEntry + 0x10, 0x10);
				DWORD cbExpSize = (*(DWORD*)(pbExpansionEntry + 0x18));
				PBYTE pbExpansion = (PBYTE)XPhysicalAllocM(cbExpSize + 0x20); // macro for XPhysicalAlloc
				memcpy(pbExpansion, pbExpansionEntry, 0x20);
				QWORD pqwExpCodeStartAdd = pqwExpHdrAdd + (*(DWORD*)(pbExpansionEntry + 4));
				Hvx::HvPeekBytes(pqwExpCodeStartAdd, pbExpansion + 0x20, cbExpSize);

				printf("Saving expansion entry...\n");
				char* filename;
				if (dwExpansion == -1 || dwExpansion > 3)
					filename = (char*)va("Hdd:\\XeKeys\\ExpEntry_%d_%08X.bin", i, dwExpID).c_str();
				else
					filename = (char*)va("Hdd:\\XeKeys\\ExpEntry_%d_%08X.bin", dwExpansion, dwExpID).c_str();
				if (!CWriteFile(filename, pbExpansion, cbExpSize + 0x20))
					printf("Couldn't save expansion entry\n");

				XPhysicalFree(pbExpansion);

				// Stop looking unless we're dumping all
				if (dwExpansion != -1)
					break;
			}

			pqwExpansionTblAdd += 0x10;
		}
	}
}