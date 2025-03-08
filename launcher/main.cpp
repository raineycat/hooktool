#include <iostream>
#include <sstream>
#include <Windows.h>

#ifndef NDEBUG
#define HOLD_CONSOLE_OPEN
#endif

int main(int argc, char** argv) {
	if (argc <= 1) {
		std::cout << "Not enough arguments provided!" << std::endl;
#ifdef HOLD_CONSOLE_OPEN
		std::cout << "Press enter to exit..." << std::endl;
		std::cin.get();
#endif
		exit(1);
	}

	std::cout << "Starting..." << std::endl;

	std::stringstream commandLine;

	// add quote marks around the target path if it doesn't have them
	// (because winapi is picky)
	if (strstr(argv[1], "\"") == nullptr) {
		commandLine << '"' << argv[1] << '"';
	}
	else {
		commandLine << argv[1];
	}

	// add any additional args
	if (argc > 2) {
		for (int i = 2; i < argc; i++) {
			commandLine << " " << std::string(argv[i]);
		}
	}

	std::cout << "commandLine = '" << commandLine.str() << "'" << std::endl;

	// start target
	STARTUPINFOA startupInfo{ 0 };
	startupInfo.cb = sizeof(STARTUPINFOA);

	PROCESS_INFORMATION procInfo{ 0 };

	char* actualCommandLine = strdup(commandLine.str().c_str());
	if (!actualCommandLine) {
		std::cout << "Failed to build command line!" << std::endl;
#ifdef HOLD_CONSOLE_OPEN
		std::cout << "Press enter to exit..." << std::endl;
		std::cin.get();
#endif
		exit(1);
	}

	BOOL success = CreateProcessA(
		nullptr,
		actualCommandLine,
		nullptr,
		nullptr,
		FALSE,
		CREATE_SUSPENDED,
		nullptr,
		nullptr,
		&startupInfo,
		&procInfo
	);

	if (!success) {
		std::cout << "Failed to start the target process: " << GetLastError() << std::endl;
#ifdef HOLD_CONSOLE_OPEN
		std::cout << "Press enter to exit..." << std::endl;
		std::cin.get();
#endif
		exit(1);
	}

	std::cout << "Target process created!" << std::endl;

	std::string targetDll = "HookToolClientDLL.dll";

	// allocate space inside the target
	LPVOID targetSpace = VirtualAllocEx(
		procInfo.hProcess,
		nullptr,
		targetDll.size() + 1,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	if (!targetSpace) {
		std::cout << "Failed to allocate memory in the target!" << std::endl;
		goto cleanup;
	}

	success = WriteProcessMemory(
		procInfo.hProcess,
		targetSpace,
		targetDll.c_str(),
		targetDll.size() + 1,
		nullptr
	);

	if (!success) {
		std::cout << "Failed to copy the injector data!" << std::endl;
		goto cleanup;
	}

	std::cout << "Copied injector data into the target process" << std::endl;

	HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
	if (!hKernel32) {
		std::cout << "Failed to load kernel32!" << std::endl;
		goto cleanup;
	}

	FARPROC hLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
	if (!hLoadLibraryA) {
		std::cout << "Failed to load LoadLibraryA!" << std::endl;
		goto cleanup;
	}

	DWORD injectorThreadId = 0;
	HANDLE injectorThread = CreateRemoteThread(
		procInfo.hProcess,
		nullptr,
		0,
		(LPTHREAD_START_ROUTINE)hLoadLibraryA,
		targetSpace,
		CREATE_SUSPENDED,
		&injectorThreadId
	);

	if (!injectorThread) {
		std::cout << "Failed to set up the injector thread!" << std::endl;
		goto cleanup;
	}

	std::cout << "Setup the injector thread!" << std::endl;
	SetThreadDescription(injectorThread, L"HookToolLauncher Injector Thread");

	// run the injector
	std::cout << "Starting injector..." << std::endl;
	ResumeThread(injectorThread);

	// let the target process run
	std::cout << "Starting target..." << std::endl;
	ResumeThread(procInfo.hThread);

	// wait for user input
	std::cout << "Press enter to end the target process..." << std::endl;
	std::cin.get();

	// cleanup
	std::cout << "Cleaning up..." << std::endl;
cleanup:
	free(actualCommandLine);

	TerminateProcess(procInfo.hProcess, EXIT_SUCCESS);
	CloseHandle(procInfo.hProcess);
	CloseHandle(procInfo.hThread);
	CloseHandle(injectorThread);
	FreeLibrary(hKernel32);

	// keep the console open
#ifdef HOLD_CONSOLE_OPEN
	std::cout << "Press enter to exit..." << std::endl;
	std::cin.get();
#endif
}
