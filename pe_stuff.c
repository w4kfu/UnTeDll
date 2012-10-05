#include "pe_stuff.h"

int openPE(char *name, struct pe_file *pef)
{
    if (!name)
        return 0;
    pef->name = (char*)malloc(sizeof (char) * (strlen(name) + 1));
    if (!pef->name)
        return 0;
    strncpy(pef->name, name, strlen(name));
    pef->hfile = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
   	if (pef->hfile == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFileA() failed\n");
		return 0;
	}
	pef->hmap = CreateFileMappingA(pef->hfile, 0, PAGE_READONLY, 0, 0, 0);
	if (pef->hmap == NULL)
    {
		printf("[-] CreateFileMapping() failed : %d\n", GetLastError());
		return 0;
	}
	pef->map = (char*)MapViewOfFile(pef->hmap, FILE_MAP_READ, 0, 0, 0);
	if (!pef->map)
	{
		printf("[-] MapViewOfFile() failed\n");
		return 0;
	}
	/* save usefull information */
	pef->VirtualAddress_ls = get_last_section((HMODULE)pef->map);
    pef->sect_align = (DWORD)ParsePE((HMODULE)pef->map, SECTION_ALIGNMENT);
	pef->saved_header = (char*)malloc(sizeof(char) * pef->sect_align);
    if (!pef->saved_header)
        return 0;
    memcpy(pef->saved_header, pef->map, pef->sect_align);
	return 1;
}

void closePE(struct pe_file *pef)
{
    free(pef->name);
	UnmapViewOfFile(pef->map);
	CloseHandle(pef->hmap);
	CloseHandle(pef->hfile);
}

void* ParsePE(HMODULE hMod, int champ)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pPE;
    WORD SOptHdr;

    if (pDosHeader->e_magic != 'ZM')
        return (void*)0x0BADC0DE;
    pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)hMod);
    if (pPE->Signature != 'EP')
        return (void*)0x0BADC0DE;
    switch(champ)
    {
        case MZ_HEADER:
            return (void*)pDosHeader;
        case PE_HEADER:
            return (void*)pPE;
        case MACHINE:
            return (void*)pPE->FileHeader.Machine;
        case NMB_OF_SECTIONS:
            return (void*)pPE->FileHeader.NumberOfSections;
        case TDS:
            return (void*)pPE->FileHeader.TimeDateStamp;
        case POINTER_TO_SYMBOL_TABLE:
            return (BYTE *)pPE->FileHeader.PointerToSymbolTable + (DWORD)hMod;
        case NMB_OF_SYMBOLS:
            return (void*)pPE->FileHeader.NumberOfSymbols;
        case CHARACTERISTICS:
            return (void*)pPE->FileHeader.Characteristics;
        default:
            break;
    }
    SOptHdr = pPE->FileHeader.SizeOfOptionalHeader;
    switch(champ)
    {
        case MAGIC:
            if (SOptHdr >= OptHdrMinSize(Magic))
                return (void*)pPE->OptionalHeader.Magic;
            else
                return (void*)0x0BADC0DE;
        case MAJ_LINKER_V:
            if (SOptHdr >= OptHdrMinSize(MajorLinkerVersion))
                return (void*)pPE->OptionalHeader.MajorLinkerVersion;
            else
                return (void*)0x0BADC0DE;
        case MIN_LINKER_V:
            if (SOptHdr >= OptHdrMinSize(MinorLinkerVersion))
                return (void*)pPE->OptionalHeader.MinorLinkerVersion;
            else
                return (void*)0x0BADC0DE;
        case SIZE_OF_CODE:
            if (SOptHdr >= OptHdrMinSize(SizeOfCode))
                return (void*)pPE->OptionalHeader.SizeOfCode;
            else
                return (void*)0x0BADC0DE;
        case SIZE_OF_INITIALIZED_DATA:
            if (SOptHdr >= OptHdrMinSize(SizeOfInitializedData))
                return (void*)pPE->OptionalHeader.SizeOfInitializedData;
            else
                return (void*)0x0BADC0DE;
        case SIZE_OF_UNINITIALIZED_DATA:
            if (SOptHdr >= OptHdrMinSize(SizeOfUninitializedData))
                return (void*)pPE->OptionalHeader.SizeOfUninitializedData;
            else
                return (void*)0x0BADC0DE;
        case ADDR_OF_EP:
            if (SOptHdr >= OptHdrMinSize(AddressOfEntryPoint))
                return (BYTE *)pPE->OptionalHeader.AddressOfEntryPoint;
            else
                return (void*)0x0BADC0DE;
        case BASE_OF_CODE:
            if (SOptHdr >= OptHdrMinSize(BaseOfCode))
                return (BYTE*)pPE->OptionalHeader.BaseOfCode + (DWORD)hMod;
            else
                return (void*)0x0BADC0DE;
        case BASE_OF_DATA:
            if (SOptHdr >= OptHdrMinSize(BaseOfData))
                return (BYTE*)pPE->OptionalHeader.BaseOfData + (DWORD)hMod;
            else
                return (void*)0x0BADC0DE;
        case IMAGE_BASE:
            if (SOptHdr >= OptHdrMinSize(ImageBase))
                return (void*)pPE->OptionalHeader.ImageBase;
            else
                return (void*)0x0BADC0DE;
        case SECTION_ALIGNMENT:
            if (SOptHdr >= OptHdrMinSize(SectionAlignment))
                return (void*)pPE->OptionalHeader.SectionAlignment;
            else
                return (void*)0x0BADC0DE;
        case FILE_ALIGNMENT:
            if (SOptHdr >= OptHdrMinSize(FileAlignment))
                return (void*)pPE->OptionalHeader.FileAlignment;
            else
                return (void*)0x0BADC0DE;
    }
    return (void*)0x0BADC0DE;
}

int check_is_dll(struct pe_file *pef)
{
    WORD    Characteristics;

    if ((Characteristics = (WORD)ParsePE((HMODULE)pef->map, CHARACTERISTICS)) != 0x0BADC0DE)
    {
        if (Characteristics & 0x2000)
        {
            pef->is_dll = 1;
        }
        else
            pef->is_dll = 0;
    }
    else
        return 0;
    return 1;
}

unsigned int get_last_section(HMODULE hMod)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pIsh;

    if (pDosHeader->e_magic != 'ZM')
        return 0;
    pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)hMod);
    if (pPE->Signature != 'EP')
        return 0;
   pIsh = (IMAGE_SECTION_HEADER*)((BYTE*)pPE + sizeof (IMAGE_NT_HEADERS) + sizeof (IMAGE_SECTION_HEADER) * (pPE->FileHeader.NumberOfSections - 1));
   return (pIsh->VirtualAddress);
}

int scan_pattern(BYTE *addr)
{
    int i;
    unsigned int value;

    for (i = 0; i < 0x50; i++)
    {
        /*  MOV EAX, XX XX XX XX
            INC EAX
            PUSH DWORD PTR DS:[EAX]
            RET */
        if (*addr == 0xB8 && *(addr + 5) == 0x40 && *(addr + 6) == 0xFF && *(addr + 7) == 0x30 && *(addr + 8) == 0xC3)
        {
            value = *(addr + 4) << 0x18 | *(addr + 3) << 0x10 | *(addr + 2) << 0x8  | *(addr + 1);
            value = value + 1;
            return value;
        }
        addr++;
    }
    return 0;
}

int fix_imports(HMODULE mod)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER ptxt;
    PIMAGE_SECTION_HEADER prdata;
    unsigned int i;
    BYTE    *op;
    DWORD   rva;
    DWORD   api_addr;
    int count = 0;
    DWORD   oldProtect;

    pDosHeader = (PIMAGE_DOS_HEADER)mod;
    pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)mod);
    ptxt = (PIMAGE_SECTION_HEADER)((BYTE*)pPE + sizeof (IMAGE_NT_HEADERS));
    prdata = (PIMAGE_SECTION_HEADER)((BYTE*)pPE + sizeof (IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER));
    for (i = 0; i < ptxt->Misc.VirtualSize; i++)
    {
        op = (BYTE*)mod + ptxt->VirtualAddress + i;
        if ((*op == 0xFF && *(op + 1) == 0x15) || (*op == 0xFF && *(op + 1) == 0x25) || (*op == 0x8B && *(op + 1) == 0x2D))
        {
            rva = *(op + 5) << 0x18 | *(op + 4) << 0x10 | *(op + 3) << 0x8  | *(op + 2);
            if (rva >= (prdata->VirtualAddress + (DWORD)mod) && rva <= (prdata->VirtualAddress + (DWORD)mod + prdata->Misc.VirtualSize))
            {
                api_addr = scan_pattern((BYTE*)(*(DWORD*)rva));
                if (api_addr)
                {
                    printf("Find CALL DWORD PTR[%X] at Addr %X ; [%X] = %X\n", rva, ((BYTE*)mod + ptxt->VirtualAddress + i), api_addr, *(DWORD*)api_addr);
                    VirtualProtect((LPVOID)rva, 4, 0x40, &oldProtect);
                    *(DWORD*)rva = *(DWORD*)api_addr;
                    VirtualProtect((LPVOID)rva, 4, oldProtect, &oldProtect);
                }
                count++;
            }
        }
    }
    printf("count = %d\n", count);
    return 1;
}
