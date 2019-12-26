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

	std::unique_ptr<SectionHeader_t> text;
	std::unique_ptr<SectionHeader_t> invalid;

	auto status = STATUS_SUCCESS_I;

	PeParser pe{ std::string{argv[1]} };

	pe.parse();

	text = pe.get_section_header_by_name(".text");
	invalid = pe.get_section_header_by_name(".fake");

	if (text)
	{
		std::cout << ".text is valid\n";
		std::cout << text.get()->PointerToRawData << '\n';
		std::cout << text.get()->VirtualSize << '\n';
		std::cout << text.get()->SizeOfRawData << '\n';
	}

	if (invalid)
	{
		std::cout << ".fake is valid\n";
	}

	return status;
}