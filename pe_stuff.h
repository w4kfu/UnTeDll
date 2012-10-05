#ifndef PE_STUFF_H_
#define PE_STUFF_H_

#include <windows.h>
#include <stdio.h>

enum CHAMPS_PE
{
    MZ_HEADER = 0,
    PE_HEADER,
    MACHINE,
    NMB_OF_SECTIONS,
    TDS,
    POINTER_TO_SYMBOL_TABLE,
    NMB_OF_SYMBOLS,
    CHARACTERISTICS,
    MAGIC,
    MAJ_LINKER_V,
    MIN_LINKER_V,
    SIZE_OF_CODE,
    SIZE_OF_INITIALIZED_DATA,
    SIZE_OF_UNINITIALIZED_DATA,
    ADDR_OF_EP,
    BASE_OF_CODE,
    BASE_OF_DATA,
    IMAGE_BASE,
    SECTION_ALIGNMENT,
    FILE_ALIGNMENT
    /* [...] */
};

struct pe_file
{
    char *name;
    HANDLE hfile;
    HANDLE hmap;
    char *map;
    unsigned int VirtualAddress_ls;
    int   is_dll;
    DWORD sect_align;
    char *saved_header;
};

#define OptHdrMinSize(a) ((int)(&pPE->OptionalHeader.##a) + sizeof(pPE->OptionalHeader.##a) - (int)(&pPE->OptionalHeader))

int openPE(char *name, struct pe_file *pef);
void closePE(struct pe_file *pef);
void* ParsePE(HMODULE hMod, int champ);
int check_is_dll(struct pe_file *pef);
int CreateProc(struct pe_file *pef, char *dll_name);
unsigned int get_last_section(HMODULE hMod);
int fix_imports(HMODULE mod);
int scan_pattern(BYTE *addr);

#endif // PE_STUFF_H_
