
#include "WSDApi.h"
#include <psdk/winnls.h>
BOOL
WINAPI
DllMain(HANDLE hDll,
        DWORD dwReason,
        LPVOID lpReserved)
{
    /* For now, there isn't much to do */
    if (dwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hDll);
    return TRUE;
}
