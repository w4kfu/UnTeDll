#include <stdio.h>
#include <stdlib.h>
#include "pe_stuff.h"
#include "hook_stuff.h"

HMODULE mod;
struct pe_file pef;

int main(int argc, char *argv[])
{
    DWORD dest;
    DWORD oep;
    DWORD oldprotect;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;

    if (argc != 2)
    {
        printf("Usage : %s <telock_file>\n", argv[0]);
        return 1;
    }
    if (!openPE(argv[1], &pef))
    {
        return 1;
    }
    if (!check_is_dll(&pef))
    {
        return 1;
        closePE(&pef);
    }
    if (pef.is_dll)
    {
        setup_Hook_VirtualFree();
        setup_Hook_VirtualProtect();
        mod = LoadLibraryA(pef.name);
        printf("MOD = %X\n", mod);
        dest = *(DWORD*)((BYTE*)mod + pef.VirtualAddress_ls + 1);
        oep = dest + ((DWORD)mod + pef.VirtualAddress_ls + 5) - (DWORD)mod;
        /* delete offset first section ? */
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
    }
    else
    {
        printf("[-] Not implemented\n");
    }
    return 0;
}
