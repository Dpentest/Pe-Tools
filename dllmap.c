#include "stdafx.h"
#include <Windows.h>

BOOL FileMap(LPWSTR File, LPWSTR SpoofFile)
{
	HANDLE hFile = CreateFileW(File, GENERIC_READ, FILE_ATTRIBUTE_NORMAL, 0 , OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("Can not read: ", File);
		return FALSE;
	}

	BOOL bRet = FALSE;

	HANDLE hMapping = CreateFileMapping(hFile , 0, PAGE_WRITECOPY, 0, 0, 0);
	if (hFile)
	{
		LPVOID pMem = MapViewOfFile(hMapping , FILE_MAP_COPY, 0, 0, 0);
		if (pMem)
		{
			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)pMem;
                        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pDosHead + (DWORD)pDosHead->e_lfanew);
                        PIMAGE_FILE_HEADER pFileHead = (PIMAGE_FILE_HEADER)&pNt->FileHeader;
			if (pDosHead->e_magic != 0x5A4D && pNt->Signature == IMAGE_NT_SIGNATURE)
			{
				wprintf_s(L"PE file invalid");
				return FALSE;
			}
            
			pFileHead->Characteristics |= IMAGE_FILE_DLL; // set dll flag 
			
				HANDLE hTargetFile = CreateFileW(SpoofFile, GENERIC_WRITE, FILE_ATTRIBUTE_HIDDEN, 0,  CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
				if (hTargetFile != INVALID_HANDLE_VALUE)
				{
					DWORD dwWritten;
					DWORD dwFileSize = GetFileSize(hFile, 0);
					bRet = WriteFile(hTargetFile, pMem, dwFileSize, &dwWritten, 0);
					CloseHandle(hTargetFile);
				}
				else
				{
					wprintf_s(L"Can not create target file: ", SpoofFile);
				}
			
			UnmapViewOfFile(pMem);
		}
		else
		{
			wprintf_s(L"Can not map to memory");
		}

		CloseHandle(hMapping);
	}
	else
	{
		wprintf_s(L"Can not create filemapping");
	}
	CloseHandle(hFile);
	return bRet;
}

VOID Help()
{
	wprintf_s(L"DllMap - Hide dll inside non suspicious looking files heh\n")
	wprintf_s(L"DllMap [path to dll] [path to file ex: abc.jpg]\n");
	wprintf_s("\n");

}

int wmain(int argc, wchar_t *argv[])
{
	if (argc < 3)
		return Help();
    
    FileMap(argv[1], argv[2]);
    
    return 0;
}
