#pragma once
#undef UNICODE
#define UNICODE

#define DllExport extern "C" __declspec(dllexport)
PIMAGE_SECTION_HEADER stSectionHeader;
DWORD oldProtection;
std::wstring moduleName;
#pragma comment(lib, "ImageHlp")
