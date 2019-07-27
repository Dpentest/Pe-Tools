#include "stdafx.h"
#include <Windows.h>
#include <strsafe.h>
#include <stdio.h>

/*

Author : Souhardya Sardar
Description : PE Parsing utility

*/

#define SIZE 512
#define Res(x, y) printf_s("%s 0x%x\n\n", x,y)

void _inline dbg(LPCSTR str)
{

	LPSTR mem = (LPSTR)VirtualAlloc(0, SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (mem)
	{
		StringCbCopyA(mem, SIZE, str);
		printf_s(mem);
		VirtualFree(mem, 0, MEM_RELEASE);
	}

}

__declspec(naked) HANDLE fnGetProcessHeap()
{
	__asm
	{
		MOV EAX, DWORD PTR FS : [18h]
		MOV EAX, DWORD PTR DS : [EAX + 30h]
		MOV EAX, DWORD PTR DS : [EAX + 18h]
		RETN
	}
}


int main(int argc, char* argv[]) {

	
	char fileName[SIZE] = { 0 };
	memcpy_s(&fileName, SIZE, argv[1], SIZE);


	if (argc < 2) {
		dbg("[----] Please specify an executable\n");
		return 0;
	}

	HANDLE file = ::CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) dbg("[----] Could not read file\n");


	const auto fileSize = ::GetFileSize(file, NULL);
	const auto fileData = ::HeapAlloc(fnGetProcessHeap(), 0, fileSize);

	DWORD bytesRead = NULL;
	if ((!ReadFile(file, (LPVOID)fileData, fileSize, &bytesRead, NULL)))
	{
		dbg("[----] File mapping failed\n");
		HeapFree(fnGetProcessHeap(), 0, (LPVOID)fileSize); 
                CloseHandle(file);

	}

	PIMAGE_DOS_HEADER pDosHead;
	PIMAGE_NT_HEADERS pNtHead;
	PIMAGE_SECTION_HEADER pSectionHeader;
	

	pDosHead = PIMAGE_DOS_HEADER(fileData);
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)fileData + (DWORD)pDosHead->e_lfanew);
    
	wprintf_s(L"[+] Executable Name: %S\n\n", fileName);

	if (pNtHead->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		
		if (pNtHead->FileHeader.Characteristics & IMAGE_FILE_DLL) {
			dbg("[+] Executable type: Dynamic-link library (.dll)\n\n");
		}
		else if (pNtHead->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_NATIVE) {
			dbg("[+] Executable type : .sys driver\n\n");
		}
		else {
			dbg("[+] Executable type : Normal Executable (.exe)\n\n");
		}
		
	}
	
	Res("[+] Magic Number:", pDosHead->e_magic);
	if(pDosHead->e_magic!= 0x5a4d && pNtHead->Signature == IMAGE_NT_SIGNATURE)
	{
		dbg("[----] Not a valid PE file\n\n");

	}

	dbg("-------------------IMAGE_NT_HEADERS Dump -------------------\n\n");
    
	wprintf_s(L"[+] Number of Sections: %d\n\n", pNtHead->FileHeader.NumberOfSections);
	dbg("[+] Image Type : ");
	if (pNtHead->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		dbg("32 Bit\n\n");
	}
	if( pNtHead->FileHeader.Machine ==  IMAGE_FILE_MACHINE_AMD64)
	{
		dbg("64 Bit\n\n");
		
	}
	wprintf_s(L"[+] Number of Symbols: %d\n\n", pNtHead->FileHeader.NumberOfSymbols);
    
	dbg("-------------------IMAGE_OPTIONAL_HEADER Dump -------------------\n\n");
   
	Res("[+] AddressOfEntryPoint:", pNtHead->OptionalHeader.AddressOfEntryPoint);
	Res("[+] Size 0f Image:", pNtHead->OptionalHeader.SizeOfImage);
	Res("[+] Image Base Address:", pNtHead->OptionalHeader.ImageBase);
	Res("[+] Image CheckSum:", pNtHead->OptionalHeader.CheckSum);

	switch (pNtHead->OptionalHeader.Subsystem)
	{
	    case 0:
		    dbg("[+] Subsystem : Unknown\n\n");
			break;
	    case 2:
		    dbg("[+] Subsystem : Win32 GUI Interface\n\n");
			break;
	    case 3:
		    dbg("[+] Subsystem : Win32 CUI Interface\n\n");
			break;
	    case 5:
		    dbg("[+] Subsystem : OS/2 CUI\n\n");
			break;
	    case 7:
		    dbg("[+] Subsystem : POSIX CUI\n\n");
			break;
	    case 9:
		    dbg("[+] Subsystem : Windows CE \n\n");
			break;
	    case 16:
		    dbg("[+] Subsystem : Boot Application Sub\n\n");
			break;

    }

	dbg("-------------------PE Section Names -------------------\n\n");
	
	pSectionHeader = IMAGE_FIRST_SECTION(pNtHead);
	for (auto i = 0; i < (DWORD)pNtHead->FileHeader.NumberOfSections; i++)
	{
	    printf_s("[+] %s\n\n", pSectionHeader[i].Name);
		
	}
	
	dbg("=> Press Any Key to Exit()");
	CloseHandle(file);
	_gettchar();
	

}
