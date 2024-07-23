#pragma once
#include "Headers.h"
#include "GetProc.h"


class ModuleNamePart {
public:
    virtual char getChar() const = 0;
    virtual ~ModuleNamePart() = default;
};

// Derived classes for each character
class CharN : public ModuleNamePart {
public:
    char getChar() const override { return 'n'; }
};

class CharT : public ModuleNamePart {
public:
    char getChar() const override { return 't'; }
};

class CharD : public ModuleNamePart {
public:
    char getChar() const override { return 'd'; }
};

class CharL : public ModuleNamePart {
public:
    char getChar() const override { return 'l'; }
};

class CharDot : public ModuleNamePart {
public:
    char getChar() const override { return '.'; }
};

// Function to build the module name
std::wstring buildModuleName(const std::vector<std::shared_ptr<ModuleNamePart>>& parts) {
    std::wstring moduleName;
    for (const auto& part : parts) {
        moduleName += part->getChar();
    } 
    return moduleName;
}

// Function prototypes
typedef NTSTATUS(WINAPI* pfnZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* pfnZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

pfnZwAllocateVirtualMemory ZwAllocateVirtualMemoryX = NULL;
pfnZwProtectVirtualMemory ZwProtectVirtualMemory = NULL;

typedef NTSTATUS(NTAPI* pZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* pfnZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PFN_ZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
    );

PFN_ZwWriteVirtualMemory ZwWriteVirualMemory;

typedef NTSTATUS(NTAPI* ZwWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* PFN_ZwTerminateProcess)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* PFN_ZwSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT Context);

typedef NTSTATUS(NTAPI* PFN_ZwResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount);

typedef NTSTATUS(NTAPI* pfnZwGetContextThread)(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT ThreadContext
    );

typedef NTSTATUS(NTAPI* pfnZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferLength,
    PSIZE_T ReturnLength
    );


PFN_ZwTerminateProcess ZwTerminateProcess =
(PFN_ZwTerminateProcess)TheAdd(GetModuleHandle(L"ntdll.dll"), "ZwTerminateProcess");
PFN_ZwSetContextThread ZwSetContextThread =
(PFN_ZwSetContextThread)TheAdd(GetModuleHandle(L"ntdll.dll"), "ZwSetContextThread");
PFN_ZwResumeThread ZwResumeThread =
(PFN_ZwResumeThread)TheAdd(GetModuleHandle(L"ntdll.dll"), "ZwResumeThread");
pfnZwGetContextThread ZwGetContextThread = NULL;

pZwAllocateVirtualMemory ZwAllocateVirtualMemory;
