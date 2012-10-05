#include "hook_stuff.h"

extern HMODULE mod;
extern struct pe_file pef;
int initialized = 0;
PVOID ExcptAddr = NULL;
PVOID Handler;

BOOL (__stdcall *Resume_VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) = NULL;
BOOL (__stdcall *Resume_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = NULL;

unsigned long hookHandler(PEXCEPTION_POINTERS exc)
{
    DWORD OldProtect;
    DWORD oep;
    DWORD oldprotect;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;

    if (exc->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        /*if (ExcptAddr)
        {
            VirtualProtect((LPVOID)0x101BF000, 1, PAGE_READONLY, &OldProtect);
            ExcptAddr = NULL;
            return EXCEPTION_CONTINUE_EXECUTION;
        }*/
    }
    else if (exc->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
        printf("Exception Address = %X\n", exc->ExceptionRecord->ExceptionAddress);
        ExcptAddr = exc->ExceptionRecord->ExceptionAddress;
        VirtualProtect((LPVOID)0x101BF000, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
        printf("JUMP TO OEP !\n");
        oep = exc->ContextRecord->Ebx;
        mod = (HMODULE)0x10000000;
        printf("EBX = %X\n", exc->ContextRecord->Ebx);
        printf("MOD = %X\n", mod);
        printf("OEP = %X\n", oep);
        VirtualProtect(mod, pef.sect_align, 0x40, &oldprotect);
        memcpy(mod, pef.saved_header, pef.sect_align);
        pDosHeader = (PIMAGE_DOS_HEADER)mod;
        pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)mod);
        fix_imports(mod);
        pPE->OptionalHeader.AddressOfEntryPoint = oep;
        __asm
        {
            jmp $
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL __stdcall Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    DWORD	return_addr;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
    return (Resume_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect));
}

BOOL __stdcall Hook_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    DWORD	return_addr;
    DWORD   OldProtect;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
    if (!initialized)
    {
        initialized = 1;
        Handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)hookHandler);
        VirtualProtect((LPVOID)0x101BF000, 1, PAGE_READONLY, &OldProtect);
    }
	return (Resume_VirtualFree(lpAddress, dwSize, dwFreeType));
}

void	setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr)
{
	DWORD	OldProtect;
	DWORD	len;
	FARPROC	Proc;

	if (addr != 0)
	{
		Proc = (FARPROC)addr;
	}
	else
	{
		Proc = GetProcAddress(GetModuleHandleA(module), name_export);
		if (!Proc)
		{
		    printf("[-] Failed GetProcAddress");
		    return;
		}
	}
	len = 0;
	while (len < 5)
		len += LDE((BYTE*)Proc + len , LDE_X86);
	memcpy(trampo, Proc, len);
	*(BYTE *)((BYTE*)trampo + len) = 0xE9;
	*(DWORD *)((BYTE*)trampo + len + 1) = (BYTE*)Proc - (BYTE*)trampo - 5;
	VirtualProtect(Proc, len, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD*)((char*)Proc + 1) = (BYTE*)Hook_func - (BYTE*)Proc - 5;
	VirtualProtect(Proc, len, OldProtect, &OldProtect);
}

void setup_Hook_VirtualFree(void)
{
	Resume_VirtualFree = (BOOL(__stdcall *)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_VirtualFree, 0x90, 0x1000);
	setup_hook("kernel32.dll", "VirtualFree", &Hook_VirtualFree, Resume_VirtualFree, 0);
}

void setup_Hook_VirtualProtect(void)
{
	Resume_VirtualProtect = (BOOL(__stdcall *)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_VirtualProtect, 0x90, 0x1000);
	setup_hook("kernel32.dll", "VirtualProtect", &Hook_VirtualProtect, Resume_VirtualProtect, 0);
}
