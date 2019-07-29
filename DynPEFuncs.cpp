#include "stdafx.h"
#include <Windows.h>


/** Custom Wrappers for GetModuleHandleW && GetProcAddress **/ 


struct CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

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

//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
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

//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
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

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
};

//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
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

	while(ListHead != pLdrMod)
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
