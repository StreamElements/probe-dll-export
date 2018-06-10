#include <windows.h>
#include <strsafe.h>

#include <iostream>
#include <string>

void print_error(LPTSTR label)
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)label) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		label, dw, lpMsgBuf);

	std::cerr << (LPCTSTR)lpDisplayBuf << std::endl;

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
}

int main(int argc, char* argv[])
{
	int exit_code = 1;

	if (argc != 3) {
		std::cout << "Usage: " << argv[0] << " path-to.dll exported_function_name" << std::endl;
	}
	else {
		exit_code = 2;

		std::string path = argv[1];
		std::string func_name = argv[2];

		size_t index = path.find_last_of('\\');
		std::string folder_path = path.substr(0, index);
		if (!folder_path.size()) {
			folder_path = ".";
		}

		if (SetCurrentDirectory(folder_path.c_str())) {
			exit_code = 3;

			HMODULE hModule = LoadLibrary(path.c_str());
			if (hModule != NULL) {
				exit_code = 4;

				FARPROC pProc = GetProcAddress(hModule, func_name.c_str());

				if (pProc != NULL) {
					exit_code = 0;
				}
				else print_error("GetProcAddress");

				FreeLibrary(hModule);
			}
			else print_error("LoadLibrary");
		}
		else print_error("SetCurrentDirectory");
	}

	return exit_code;
}
