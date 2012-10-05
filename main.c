#include <stdio.h>
#include <stdlib.h>
#include "pe_stuff.h"
#include "hook_stuff.h"

struct pe_file pef;

int main(int argc, char *argv[])
{
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
        LoadLibraryA(pef.name);
    }
    else
    {
        printf("[-] Not implemented (only dll)\n");
    }
    return 0;
}
