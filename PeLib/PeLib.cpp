// PeLib.cpp
// Portable Executable parsing library implementation.

#include <windows.h>
#include <memory>
#include <vector>
#include <string>
#include <iostream>

#include "PeLib.h"

/* ----------------------------------------------------------------------------
 *	Special Member Functions
 */

PELIB_API 
PeParser::PeParser(const std::string& file_path)
	: file_path{ file_path }
{
	DbgPrint("PeParser initialized");
}

PELIB_API 
PeParser::~PeParser()
{
	DbgPrint("PeParser destroyed");
}

/* ----------------------------------------------------------------------------
 *	Top-Level Parsing Routine
 */

PELIB_API PeParseResult
PeParser::parse()
{
	DbgPrint("Initiating default parse");

	HANDLE hFile;
	DWORD dwFileSize;
	std::unique_ptr<BYTE[]> pFileBuffer;

	auto result   = PeParseResult::ResultSuccess;
	auto rollback = 0;

	hFile = ::CreateFileA(
		file_path.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		result = PeParseResult::ResultFileInaccessible;
		DbgPrint("Failed to acquire handle to file");
		goto CLEANUP;
	}

	rollback = 1;

	// NOTE: fail on files > 4GB
	dwFileSize = ::GetFileSize(hFile, nullptr);
	pFileBuffer.reset(new BYTE[dwFileSize]);

	if (!::ReadFile(
		hFile,
		reinterpret_cast<LPVOID>(pFileBuffer.get()),
		dwFileSize,
		nullptr,
		nullptr
	))
	{
		result = PeParseResult::ResultFileReadFailed;
		DbgPrint("Failed to read file contents");
		goto CLEANUP;
	}

	// do a simple sanity check before beginning full parse
	if (!is_valid_pe(pFileBuffer))
	{
		result = PeParseResult::ResultFileMalformed;
		DbgPrint("Input file failed validation");
		goto CLEANUP;
	}

	// setup complete; begin parsing
	parse_dos_header(pFileBuffer);
	parse_nt_headers(pFileBuffer);
	parse_file_header(pFileBuffer);
	parse_optional_header(pFileBuffer);

CLEANUP:
	switch (rollback)
	{
	case 1:
		CloseHandle(hFile);
	case 0:
		break;
	}

	return result;
}

/* ----------------------------------------------------------------------------
 *	Exported Methods
 */

// get_machine
// Return string representation of file header machine field.
//
// Returns string representation of image machine field.
PELIB_API std::string
PeParser::get_machine()
{
	auto machine = FileHeader.Machine;

	return [&]() {
		switch (machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			return "IMAGE_FILE_MACHINE_I386";
		case IMAGE_FILE_MACHINE_IA64:
			return "IMAGE_FILE_MACHINE_IA64";
		case IMAGE_FILE_MACHINE_AMD64:
			return "IMAGE_FILE_MACHINE_AMD64";
		}
	}();
}

// get_characteristics
// Initialize a vector of strings representing the image characteristics.
//
// Returns vector of strings representing image characteristics.
PELIB_API std::unique_ptr<std::vector<std::string>>
PeParser::get_characteristics()
{
	auto& flags = FileHeader.Characteristics;
	auto characteristics = std::make_unique<std::vector<std::string>>();

	push_if_flag_set(characteristics, flags, IMAGE_FILE_RELOCS_STRIPPED, "IMAGE_FILE_RELOCS_STRIPPED");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_EXECUTABLE_IMAGE, "IMAGE_FILE_EXECUTABLE_IMAGE");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_LINE_NUMS_STRIPPED, "IMAGE_FILE_LINE_NUMS_STRIPPED");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_LOCAL_SYMS_STRIPPED, "IMAGE_FILE_LOCAL_SYMS_STRIPPED");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_AGGRESIVE_WS_TRIM, "IMAGE_FILE_AGGRESIVE_WS_TRIM");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_LARGE_ADDRESS_AWARE, "IMAGE_FILE_LARGE_ADDRESS_AWARE");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_BYTES_REVERSED_LO, "IMAGE_FILE_BYTES_REVERSED_LO");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_32BIT_MACHINE, "IMAGE_FILE_32BIT_MACHINE");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_DEBUG_STRIPPED, "IMAGE_FILE_DEBUG_STRIPPED");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_NET_RUN_FROM_SWAP, "IMAGE_FILE_NET_RUN_FROM_SWAP");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_SYSTEM, "IMAGE_FILE_SYSTEM");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_DLL, "IMAGE_FILE_DLL");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_UP_SYSTEM_ONLY, "IMAGE_FILE_UP_SYSTEM_ONLY");
	push_if_flag_set(characteristics, flags, IMAGE_FILE_BYTES_REVERSED_HI, "IMAGE_FILE_BYTES_REVERSED_HI");

	return characteristics;
}

/* ----------------------------------------------------------------------------
 *	Internal Methods
 */

// is_valid_pe
// Determine if the provided file is a valid PE image.
//
// Arguments:
//	buffer - image file buffer
//
// Returns TRUE if the executable image passes validation, false otherwise
bool PeParser::is_valid_pe(FileBuffer& buffer)
{
	// TODO: stronger validation
	return reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.get())->e_magic == IMAGE_DOS_SIGNATURE;
}

// parse_dos_header
// Parse the image DOS header.
//
// Arguments:
//	buffer - image file buffer
void PeParser::parse_dos_header(FileBuffer& buffer)
{
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.get());

	DosHeader.magic    = pDosHeader->e_magic;
	DosHeader.e_lfanew = pDosHeader->e_lfanew;
}

// parse_nt_headers
// Parse the image NT headers.
//
// Arguments:
//	buffer - image file buffer
void PeParser::parse_nt_headers(FileBuffer& buffer)
{
	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		buffer.get() 
		+ DosHeader.e_lfanew
	);

	NtHeaders.Signature = pNtHeaders->Signature;
}

// parse_file_header
// Parse the image COFF file header.
//
// Arguments:
//	buffer - image file buffer
void PeParser::parse_file_header(FileBuffer& buffer)
{
	auto header = reinterpret_cast<PIMAGE_NT_HEADERS>(
		buffer.get()              
		+ DosHeader.e_lfanew       
		)->FileHeader;

	FileHeader.Machine              = header.Machine;
	FileHeader.NumberOfSections     = header.NumberOfSections;
	FileHeader.TimeDateStamp        = header.TimeDateStamp;
	FileHeader.PointerToSymbolTable = header.PointerToSymbolTable;
	FileHeader.NumberOfSymbols      = header.NumberOfSymbols;
	FileHeader.SizeOfOptionalHeader = header.SizeOfOptionalHeader;
	FileHeader.Characteristics      = header.Characteristics;
}

// parse_optional_header
// Parse the image optional header.
//
// Arguments:
//	buffer - image file buffer
void PeParser::parse_optional_header(FileBuffer& buffer)
{
	auto magic = reinterpret_cast<PIMAGE_NT_HEADERS>(
		buffer.get()
		+ DosHeader.e_lfanew
		)->OptionalHeader.Magic;

	if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		parse_optional_header32(buffer);
	}
	else
	{
		parse_optional_header64(buffer);
	}

	// NOTE: alternatives are non-exhaustive
}

// parse_optional_header32
// Helper method to parse 32-bit version of optional header.
//
// Arguments:
//	buffer - image file buffer
void PeParser::parse_optional_header32(FileBuffer& buffer)
{
	auto pBase = reinterpret_cast<PIMAGE_NT_HEADERS>(
		buffer.get()
		+ DosHeader.e_lfanew
		)->OptionalHeader;

	auto header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&pBase);

	OptionalHeader.Magic = header->Magic;
	OptionalHeader.MajorLinkerVersion = header->MajorLinkerVersion;
	OptionalHeader.MinorLinkerVersion = header->MinorLinkerVersion;
	OptionalHeader.SizeOfCode = header->SizeOfCode;
	OptionalHeader.SizeOfInitializedData = header->SizeOfInitializedData;
	OptionalHeader.SizeOfUninitializedData = header->SizeOfUninitializedData;
	OptionalHeader.AddressOfEntryPoint = header->AddressOfEntryPoint;
	OptionalHeader.BaseOfCode = header->BaseOfCode;
	OptionalHeader.ImageBase = header->ImageBase;
	OptionalHeader.SectionAlignment = header->SectionAlignment;
	OptionalHeader.FileAlignment = header->FileAlignment;
	OptionalHeader.MajorOperatingSystemVersion = header->MajorOperatingSystemVersion;
	OptionalHeader.MinorOperatingSystemVersion = header->MinorOperatingSystemVersion;
	OptionalHeader.MajorImageVersion = header->MajorImageVersion;
	OptionalHeader.MinorImageVersion = header->MinorImageVersion;
	OptionalHeader.MajorSubsystemVersion = header->MajorSubsystemVersion;
	OptionalHeader.MinorSubsystemVersion = header->MinorSubsystemVersion;
	OptionalHeader.Win32VersionValue = header->Win32VersionValue;
	OptionalHeader.SizeOfImage = header->SizeOfImage;
	OptionalHeader.SizeOfHeaders = header->SizeOfHeaders;
	OptionalHeader.CheckSum = header->CheckSum;
	OptionalHeader.Subsystem = header->Subsystem;
	OptionalHeader.DllCharacteristics = header->DllCharacteristics;
	OptionalHeader.SizeOfStackReserve = header->SizeOfStackReserve;
	OptionalHeader.SizeOfStackCommit = header->SizeOfStackCommit;
	OptionalHeader.SizeOfHeapReserve = header->SizeOfHeapReserve;
	OptionalHeader.SizeOfHeapCommit = header->SizeOfHeapCommit;
	OptionalHeader.LoaderFlags = header->LoaderFlags;
	OptionalHeader.NumberOfRvaAndSizes = header->NumberOfRvaAndSizes;
}

// parse_optional_header64
// Helper method to parse 64-bit version of optional header.
//
// Arguments:
//	buffer - image file buffer
void PeParser::parse_optional_header64(FileBuffer& buffer)
{
	auto pBase = reinterpret_cast<PIMAGE_NT_HEADERS>(
		buffer.get()
		+ DosHeader.e_lfanew
		)->OptionalHeader;

	auto header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&pBase);

	OptionalHeader.Magic = header->Magic;
	OptionalHeader.MajorLinkerVersion = header->MajorLinkerVersion;
	OptionalHeader.MinorLinkerVersion = header->MinorLinkerVersion;
	OptionalHeader.SizeOfCode = header->SizeOfCode;
	OptionalHeader.SizeOfInitializedData = header->SizeOfInitializedData;
	OptionalHeader.SizeOfUninitializedData = header->SizeOfUninitializedData;
	OptionalHeader.AddressOfEntryPoint = header->AddressOfEntryPoint;
	OptionalHeader.BaseOfCode = header->BaseOfCode;
	OptionalHeader.ImageBase = header->ImageBase;
	OptionalHeader.SectionAlignment = header->SectionAlignment;
	OptionalHeader.FileAlignment = header->FileAlignment;
	OptionalHeader.MajorOperatingSystemVersion = header->MajorOperatingSystemVersion;
	OptionalHeader.MinorOperatingSystemVersion = header->MinorOperatingSystemVersion;
	OptionalHeader.MajorImageVersion = header->MajorImageVersion;
	OptionalHeader.MinorImageVersion = header->MinorImageVersion;
	OptionalHeader.MajorSubsystemVersion = header->MajorSubsystemVersion;
	OptionalHeader.MinorSubsystemVersion = header->MinorSubsystemVersion;
	OptionalHeader.Win32VersionValue = header->Win32VersionValue;
	OptionalHeader.SizeOfImage = header->SizeOfImage;
	OptionalHeader.SizeOfHeaders = header->SizeOfHeaders;
	OptionalHeader.CheckSum = header->CheckSum;
	OptionalHeader.Subsystem = header->Subsystem;
	OptionalHeader.DllCharacteristics = header->DllCharacteristics;
	OptionalHeader.SizeOfStackReserve = header->SizeOfStackReserve;
	OptionalHeader.SizeOfStackCommit = header->SizeOfStackCommit;
	OptionalHeader.SizeOfHeapReserve = header->SizeOfHeapReserve;
	OptionalHeader.SizeOfHeapCommit = header->SizeOfHeapCommit;
	OptionalHeader.LoaderFlags = header->LoaderFlags;
	OptionalHeader.NumberOfRvaAndSizes = header->NumberOfRvaAndSizes;
}

/* ----------------------------------------------------------------------------
 *	Utility Functions
 */

// push_if_flag_set
// Utility function to push string to vector in the 
// event that flag is set in given mask.
//
// Arguments:
//	vec   - pointer to string vector
//	flags - total flag set
//	mask  - flag set to test against
//	str   - string to push if flag present
void push_if_flag_set(
	std::unique_ptr<std::vector<std::string>>& vec,
	unsigned short flags,
	unsigned short mask,
	std::string str
)
{
	if (flags & mask)
	{
		vec.get()->push_back(str);
	}
}

