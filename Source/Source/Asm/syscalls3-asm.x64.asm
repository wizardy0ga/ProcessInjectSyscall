; This file was generated with syswhispers 3
; https://github.com/klezVirus/SysWhispers3

.code

EXTERN SW3_GetSyscallNumber: PROC

EXTERN SW3_GetSyscallAddress: PROC

NtOpenProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 055D6B1B8h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress ; Resolve function hash into syscall offset.
	mov r11, rax               ; Save the address of the syscall
	mov ecx, 055D6B1B8h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]           ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                    ; Jump to -> Invoke system call.
NtOpenProcess ENDP

NtCreateThreadEx PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0C62C8AE8h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress ; Resolve function hash into syscall offset.
	mov r11, rax               ; Save the address of the syscall
	mov ecx, 0C62C8AE8h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]           ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                    ; Jump to -> Invoke system call.
NtCreateThreadEx ENDP

NtWriteVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 009952135h        ; Load function hash into ECX.
	call SW3_GetSyscallAddress ; Resolve function hash into syscall offset.
	mov r11, rax               ; Save the address of the syscall
	mov ecx, 009952135h        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]           ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                    ; Jump to -> Invoke system call.
NtWriteVirtualMemory ENDP

NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0F316E1BDh        ; Load function hash into ECX.
	call SW3_GetSyscallAddress ; Resolve function hash into syscall offset.
	mov r11, rax               ; Save the address of the syscall
	mov ecx, 0F316E1BDh        ; Re-Load function hash into ECX (optional).
	call SW3_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]           ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                    ; Jump to -> Invoke system call.
NtAllocateVirtualMemory ENDP

end