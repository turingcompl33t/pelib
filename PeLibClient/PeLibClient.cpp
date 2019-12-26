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

	std::string machine;
	std::unique_ptr<std::vector<std::string>> characteristics;

	auto status = STATUS_SUCCESS_I;

	PeParser pe{ std::string{argv[1]} };

	pe.parse();

	machine = pe.get_machine();
	characteristics = pe.get_characteristics();

	std::cout << machine << '\n';
	for (auto& c : *characteristics.get())
	{
		std::cout << c << '\n';
	}

	return status;
}