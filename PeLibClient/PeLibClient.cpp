// PeLibClient.cpp
// Sample consumer application for Portable Executable parsing library.

#include <windows.h>

#include <iostream>

#include "PeLib.h"

#pragma comment(lib, "PeLib.lib")

constexpr auto STATUS_SUCCESS_I = 0x0;
constexpr auto STATUS_FAILURE_I = 0x1;

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout << "[-] Invalid arguments\n";
		std::cout << "[-] Usage: PeLibClient <FILE PATH>\n";
		return STATUS_FAILURE_I;
	}

	auto status = STATUS_SUCCESS_I;

	PeLib::PeParser pe{ std::string{argv[1]} };

	pe.parse();
	auto imports = pe.get_imports_from_source("advapi32.dll");

	for (auto& i : *imports.get())
	{
		std::cout << i.Name << '\n';
	}

	return status;
}