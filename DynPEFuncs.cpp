#include "stdafx.h"
#include <Windows.h>
#include <strsafe.h>
#include <iostream>

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


