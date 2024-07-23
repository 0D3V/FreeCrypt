#pragma once
#include "Headers.h"
typedef NTSTATUS(WINAPI* pZwFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Length);
pZwFlushInstructionCache ZwFlushInstructionCache = (pZwFlushInstructionCache)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwFlushInstructionCache");

unsigned int hash_function(const char* str) {
    unsigned int hash = 0;
    while (*str) {
        hash = (hash * 31) + *str;
        str++;
    }
    return hash;
}

void* get_function_address(const char* dll_name, unsigned int target_hash) {
    HMODULE module = LoadLibraryA(dll_name);
    if (!module) {
        printf("Failed to load module: %s\n", dll_name);
        return NULL;
    }

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + dos_header->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)module + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module + export_dir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)module + export_dir->AddressOfFunctions);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char* function_name = (const char*)((BYTE*)module + names[i]);
        if (hash_function(function_name) == target_hash) {
            return (void*)((BYTE*)module + functions[ordinals[i]]);
        }
    }

    return NULL;
}

FARPROC TheAdd(HMODULE Module, LPCSTR lpProcName)
{
    DWORD* dNameRVAs = 0;
    DWORD* dFunctionRVAs = 0;
    WORD* dOrdinalRVAs = 0;

    _IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = NULL;
    unsigned long cDirSize = 0;
    _LOADED_IMAGE LoadedImage;
    char* sName = NULL;

    UINT64 AddressFound = NULL;

    UINT64 ModuleBase = (UINT64)Module;

    if (!ModuleBase)
        return NULL;

    if (MapAndLoad("ntdll.dll", NULL, &LoadedImage, TRUE, TRUE))
    {
        ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

        if (ImageExportDirectory != NULL)
        {
            dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);
            dFunctionRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfFunctions, NULL);
            dOrdinalRVAs = (WORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNameOrdinals, NULL);

            for (size_t i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
            {
                sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

                if (strcmp(sName, lpProcName) == 0)
                {
                    AddressFound = ModuleBase + dFunctionRVAs[dOrdinalRVAs[i]];
                    break;
                }
            }
        }
        else
        {
            UnMapAndLoad(&LoadedImage);
            return NULL;
        }

        UnMapAndLoad(&LoadedImage);
    }

    return (FARPROC)AddressFound;
}
