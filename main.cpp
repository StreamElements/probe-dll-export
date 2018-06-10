#include <windows.h>
#include <strsafe.h>

#include <iostream>
#include <string>
#include <codecvt>

void print_error(LPWSTR label)
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(wcslen((LPCWSTR)lpMsgBuf) + wcslen((LPCWSTR)label) + 40) * sizeof(WCHAR));
	StringCchPrintfW((LPWSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(WCHAR),
		L"%s failed with error %d: %s",
		label, dw, lpMsgBuf);

	OutputDebugStringW(GetCommandLineW());
	OutputDebugStringW((LPCWSTR)lpDisplayBuf);
	OutputDebugStringW(L"\n");

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
}

int wmain(int argc, WCHAR* argv[])
{
	int exit_code = 1;

	if (argc != 3) {
		std::cout << "Usage: " << argv[0] << " path-to.dll exported_function_name" << std::endl;
	}
	else {
		exit_code = 2;

		std::wstring path = argv[1];
		std::wstring func_name = argv[2];

		size_t index = path.find_last_of('\\');
		std::wstring folder_path = path.substr(0, index);
		if (!folder_path.size()) {
			folder_path = L".";
		}

		if (SetCurrentDirectoryW(folder_path.c_str())) {
			exit_code = 3;

			HMODULE hModule = LoadLibraryW(path.c_str());
			if (hModule != NULL) {
				exit_code = 4;

				using convert_type = std::codecvt_utf8<WCHAR>;
				std::wstring_convert<convert_type, WCHAR> converter;

				std::string func_name_utf8 = converter.to_bytes(func_name);

				FARPROC pProc = GetProcAddress(hModule, func_name_utf8.c_str());

				if (pProc != NULL) {
					exit_code = 0;
				}
				else print_error(L"GetProcAddress");

				FreeLibrary(hModule);
			}
			else print_error(L"LoadLibraryW");
		}
		else print_error(L"SetCurrentDirectoryW");
	}

	return exit_code;
}

int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR     lpCmdLine,
	_In_ int       nCmdShow
)
{
	int result = 255;

	LPWSTR *sz_arglist;
	int n_args;
	sz_arglist = CommandLineToArgvW(GetCommandLineW(), &n_args);
	if (sz_arglist == NULL)
	{
		print_error(L"CommandLineToArgvW");
	}
	else
	{
		result = wmain(n_args, sz_arglist);

		LocalFree(sz_arglist);
	}
	return result;
}