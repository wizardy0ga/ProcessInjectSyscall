; This file was generated with syswhispers
; https://github.com/jthuraisamy/SysWhispers

.code

NtOpenProcess PROC
	mov rax, gs:[60h]						; Load PEB into RAX.
NtOpenProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 19045
	je  NtOpenProcess_SystemCall_10_0_19045				
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_10_0_19045:		; Windows 10.0.19045 (22H2)
 mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
	mov rax, gs:[60h]									; Load PEB into RAX.
NtAllocateVirtualMemory_Check_X_X_XXXX:               	; Check major version.
	cmp dword ptr [rax+118h], 10
	je  NtAllocateVirtualMemory_Check_10_0_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_10_0_XXXX:              	; Check build number for Windows 10.
	cmp word ptr [rax+120h], 19045
	je NtAllocateVirtualMemory_SystemCall_10_0_19045
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_SystemCall_10_0_19045:			; Windows 10.0.19045 (22H2)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_Unknown:           	; Unknown/unsupported version.
	ret
NtAllocateVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov rax, gs:[60h]								; Load PEB into RAX.
NtWriteVirtualMemory_Check_X_X_XXXX:               	; Check major version.
	cmp dword ptr [rax+118h], 10
	je  NtWriteVirtualMemory_Check_10_0_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_10_0_XXXX:              	; Check build number for Windows 10.
	cmp word ptr [rax+120h], 19045
	je  NtWriteVirtualMemory_SystemCall_10_0_19045
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_SystemCall_10_0_19045:
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_Unknown:           	; Unknown/unsupported version.
	ret
NtWriteVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
	mov rax, gs:[60h]                             ; Load PEB into RAX.
NtCreateThreadEx_Check_X_X_XXXX:                  ; Check major version.
	cmp dword ptr [rax+118h], 10
	je  NtCreateThreadEx_Check_10_0_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_10_0_XXXX:                 ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 19045
	je  NtCreateThreadEx_SystemCall_10_0_19045
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_SystemCall_10_0_19045:           ; Windows 10.0.19045 (22H2)
	mov eax, 00c1h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_Unknown:              ; Unknown/unsupported version.
	ret
NtCreateThreadEx_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateThreadEx ENDP
end