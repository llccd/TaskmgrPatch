#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <Zydis/Zydis.h>

#ifndef _CONSOLE
#define printf(...) {}
#endif

#define QUIT(x) {ret = x; goto quit;}

static HANDLE heap = 0;

static const char* patchData[] = {
	"\xA8\x00",                            //TEST AL, 0
	"\x40\xA8\x00",                        //TEST AL, 0
	"\x66\xA9\x00\x00",                    //TEST AX, 0
	"\xA9\x00\x00\x00\x00",                //TEST EAX, 0
};

typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS64 pNT, const char* str)
{
	auto pSection = IMAGE_FIRST_SECTION(pNT);

	for (DWORD64 i = 0; i < pNT->FileHeader.NumberOfSections; i++)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
			return pSection + i;

	return NULL;
}

DWORD64 pattenMatchStr(DWORD64 base, PIMAGE_SECTION_HEADER pSection, const char* str)
{
	auto rdata = base + pSection->VirtualAddress;

	for (DWORD64 i = 0; i < pSection->SizeOfRawData; i += 4)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)(rdata + i), -1, str, -1))
			return pSection->VirtualAddress + i;

	return -1;
}

BOOL searchXref(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, DWORD64 target)
{
	auto IP = base + func->BeginAddress;
	auto length = (ZyanUSize)func->EndAddress - func->BeginAddress;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[1].mem.base == ZYDIS_REGISTER_RIP &&
			operands[1].mem.disp.value + IP == target + base &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
			return 1;
	}

	return 0;
}

DWORD64 getBase(PPROCESS_INFORMATION pi)
{
	DWORD length = 0;
	PCONTEXT context;
	InitializeContext(NULL, CONTEXT_INTEGER, &context, &length);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return -1;
	void* buf = HeapAlloc(heap, 0, length);
	DWORD64 base_address = -1;
	if (InitializeContext(buf, CONTEXT_INTEGER, &context, &length) && GetThreadContext(pi->hThread, context))
		ReadProcessMemory(pi->hProcess, (void*)(context->Rdx + 16), &base_address, sizeof(DWORD64), NULL);
	HeapFree(heap, 0, buf);
	return base_address;
}

BOOL patch(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, HANDLE hProcess, DWORD64 moduleBase)
{
	DWORD64 IP = base + func->BeginAddress;
	auto length = (ZyanUSize)func->EndAddress - func->BeginAddress;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic != ZYDIS_MNEMONIC_CALL) continue;

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands))) break;
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_NOP) {
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands))) break;
			IP += instruction.length;
			length -= instruction.length;
		}

		if (instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[0].reg.value == ZYDIS_REGISTER_EAX &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == ZYDIS_REGISTER_EAX)
		{
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands))) break;

			if (instruction.operand_count != 3 ||
				operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
				operands[0].imm.is_relative != ZYAN_TRUE ||
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
				operands[1].reg.value != ZYDIS_REGISTER_RIP)
				continue;

			IP += instruction.length;
			length -= instruction.length;
			if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ) {
				IP += operands[0].imm.value.u;
			}
			else if (instruction.mnemonic != ZYDIS_MNEMONIC_JZ) continue;

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands))) break;
			IP += instruction.length;
			length -= instruction.length;
			if (instruction.operand_count != 2 ||
				operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
				operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) continue;

			ZydisRegister reg;
			if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX) {
				if (operands[0].reg.value == ZYDIS_REGISTER_EAX) reg = ZYDIS_REGISTER_AL;
				else if (operands[0].reg.value == ZYDIS_REGISTER_ECX) reg = ZYDIS_REGISTER_CL;
				else continue;
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
				if (operands[0].reg.value == ZYDIS_REGISTER_AL) reg = ZYDIS_REGISTER_AL;
				else if (operands[0].reg.value == ZYDIS_REGISTER_CL) reg = ZYDIS_REGISTER_CL;
				else continue;
			}
			else continue;

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands))) break;
			IP += instruction.length;
			length -= instruction.length;
			if (instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
				operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
				operands[0].reg.value != reg ||
				(operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
					operands[1].imm.is_relative != ZYAN_FALSE ||
					operands[1].imm.value.u != 1) &&
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
			DWORD64 len = instruction.length;
			if (len > 5) break;

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction)) ||
				instruction.mnemonic != ZYDIS_MNEMONIC_JNZ) break;

			size_t written = 0;
			DWORD64 RVA = IP - len - base;
			WriteProcessMemory(hProcess, (void*)(RVA + moduleBase), patchData[len - 2], len, &written);
			printf("Patched %llu bytes at %llX\n", written, RVA);
			return 1;
		}
	}

	return 0;
}

PRUNTIME_FUNCTION backtrace(DWORD64 base, PRUNTIME_FUNCTION func) {
	if (func->UnwindData & RUNTIME_FUNCTION_INDIRECT)
		func = (PRUNTIME_FUNCTION)(base + func->UnwindData & ~3);

	auto unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
	while (unwindInfo->Flags & UNW_FLAG_CHAININFO)
	{
		func = (PRUNTIME_FUNCTION) & (unwindInfo->UnwindCode[(unwindInfo->CountOfCodes + 1) & ~1]);
		unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
	}

	return func;
}

int main()
{
	heap = GetProcessHeap();
	if (!heap) return -1;

	int argc;
	const auto current_cmdline = GetCommandLineW();
	const auto argv = CommandLineToArgvW(current_cmdline, &argc);
	if (!argv) return -2;

	PWSTR cmdline = NULL, szApp = NULL;
	if (argc >= 2)
	{
		auto Ccmdline = StrChrW(StrStrW(current_cmdline, argv[0]) + lstrlenW(argv[0]), L' ');
		while (*Ccmdline == L' ') Ccmdline++;
		cmdline = (PWSTR)HeapAlloc(heap, 0, ((size_t)lstrlenW(Ccmdline) + 1) * sizeof(WCHAR));
		if (cmdline) lstrcpyW(cmdline, Ccmdline);
		szApp = argv[1];
	}
	else {
		WCHAR szTaskmgr[MAX_PATH];
		lstrcpyW(szTaskmgr + GetSystemDirectoryW(szTaskmgr, sizeof(szTaskmgr) / sizeof(WCHAR)), L"\\taskmgr.exe");
		szApp = szTaskmgr;
	}

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	STARTUPINFOW startupInfo = { sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION processInfo;
	DWORD creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE | DEBUG_ONLY_THIS_PROCESS;
	if (!CreateProcessW(szApp, cmdline, NULL, NULL, false, creationFlags, 0, 0, &startupInfo, &processInfo)) return -3;

	int ret = 0;
	auto hMod = LoadLibraryExW(szApp, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hMod) QUIT(-4);
	{auto base = (size_t)hMod;

	auto pDos = (PIMAGE_DOS_HEADER)base;
	auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
	auto rdata = findSection(pNT, ".rdata");
	if (!rdata) rdata = findSection(pNT, ".text");

	auto isServer = pattenMatchStr(base, rdata, "RunTimeSettings::IsServer");
	if (isServer == -1) isServer = pattenMatchStr(base, rdata, "TmGlobalSettings::IsServer");
	if (isServer == -1) QUIT(-5);
	printf("Found IsServer at %llX\n", isServer);

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) QUIT(-6);

	DEBUG_EVENT DebugEv;
	WaitForDebugEvent(&DebugEv, INFINITE);

	auto moduleBase = getBase(&processInfo);
	if (moduleBase == -1) QUIT(-7);
	printf("taskmgr base %llx\n", moduleBase);

	for (DWORD i = 0; i < FunctionTableSize; i++) {
		if (!searchXref(&decoder, base, FunctionTable + i, isServer)) continue;
		if (patch(&decoder, base, FunctionTable + i, processInfo.hProcess, moduleBase)) continue;
		auto FunctionEntry = backtrace(base, FunctionTable + i);
		if (patch(&decoder, base, FunctionEntry, processInfo.hProcess, moduleBase)) continue;
		for (DWORD j = 0; j < FunctionTableSize; j++) {
			auto FunctionEntry2 = backtrace(base, FunctionTable + j);
			if (FunctionEntry2 == FunctionTable + j || FunctionEntry2 != FunctionEntry) continue;
			if (patch(&decoder, base, FunctionTable + j, processInfo.hProcess, moduleBase)) break;
		}
	}}
quit:
	DebugSetProcessKillOnExit(FALSE);
	DebugActiveProcessStop(processInfo.dwProcessId);
	WaitForInputIdle(processInfo.hProcess, INFINITE);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	return 0;
}
