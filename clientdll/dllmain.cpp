#include <Windows.h>
#include "hooks.hpp"

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        // MessageBoxA(NULL, "Loaded HookToolClientDLL!", "HookTool", MB_ICONINFORMATION | MB_OK);

        if (!hooktool::InitHooks()) {
            MessageBoxA(NULL, "Failed to initialise WinAPI hooks!", "HookToolClientDLL", MB_ICONERROR | MB_OK);
            return FALSE;
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        hooktool::CleanupHooks();
    }

    return TRUE;
}