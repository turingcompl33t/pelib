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

	auto sections = pe.get_sections();

	for (auto& s : *sections.get())
	{
		std::cout << "Section Name:      " << s.Name << '\n';
		std::cout << "-> Section Size:   " << s.ContentSize << '\n';
		std::cout << "-> Section Offset: " << s.Header.PointerToRawData << '\n';
		std::cout << "-> Virtual Size:   " << s.Header.VirtualSize << '\n';
	}

	return status;
}