#include <MinHook.h>
#include <cstdio>
#include <Shlwapi.h>
#include <ShlObj.h>

#include "hooks.hpp"
#include "kernel32.hpp"

namespace hooktool {
	bool InitHooks() {
		if (MH_Initialize() != MH_OK) {
			return false;
		}

		if (MH_CreateHookApi(L"kernel32.dll", "CreateFileA", detours::HookedCreateFileA, (void**)&originals::pCreateFileA) != MH_OK) {
			return false;
		}

		if (MH_CreateHookApi(L"kernel32.dll", "CreateFileW", detours::HookedCreateFileW, (void**)&originals::pCreateFileW) != MH_OK) {
			return false;
		}

		if (MH_CreateHookApi(L"kernel32.dll", "CreateFile2", detours::HookedCreateFile2, (void**)&originals::pCreateFile2) != MH_OK) {
			return false;
		}
		
		if(MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
			return false;
		}

		return true;
	}

	void CleanupHooks() {
		MH_DisableHook(MH_ALL_HOOKS);
		MH_Uninitialize();
	}

	namespace detours {
		HANDLE HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
			MessageBoxA(NULL, lpFileName, "CreateFileA called:", MB_OK);
			dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_WRITE;

			HANDLE fh = originals::pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			return fh;
		}

		HANDLE HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
			MessageBoxW(NULL, lpFileName, L"CreateFileW called:", MB_OK);
			dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_WRITE;

			HANDLE fh = originals::pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			return fh;
		}

		HANDLE HookedCreateFile2(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams) {
			MessageBoxW(NULL, lpFileName, L"CreateFile2 called:", MB_OK);
			dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_WRITE;

			HANDLE fh = originals::pCreateFile2(lpFileName, dwDesiredAccess, dwShareMode, dwCreationDisposition, pCreateExParams);
			return fh;
		}
	}
}