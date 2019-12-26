// PeLib.cpp
// Portable Executable parsing library implementation.

#include <windows.h>
#include <memory>
#include <vector>
#include <string>
#include <iostream>

#include "Utility.h"
#include "PeLib.h"

namespace PeLib {

	/* ----------------------------------------------------------------------------
	 *	PeParser: Special Member Functions
	 */

	PELIB_API
	PeParser::PeParser(const std::string& file_path)
		: file_path{ file_path }
	{
		DbgPrint("PeParser initialized");

		DosHeader = { 0 };
		NtHeaders = { 0 };
		FileHeader = { 0 };
		OptionalHeader = { 0 };
	}

	PELIB_API
	PeParser::~PeParser()
	{
		DbgPrint("PeParser destroyed");
	}

	/* ----------------------------------------------------------------------------
	 *	PeParser: Top-Level Parsing Routine
	 */

	PELIB_API PeParseResult
	PeParser::parse()
	{
		DbgPrint("Initiating default parse");

		HANDLE hFile;
		DWORD dwFileSize;
		std::unique_ptr<BYTE[]> pFileBuffer;

		auto result = PeParseResult::ResultSuccess;
		auto rollback = 0;

		hFile = ::CreateFileA(
			file_path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
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
		parse_data_directory(pFileBuffer);
		parse_sections(pFileBuffer);

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
	 *	PeParser: Exported Methods
	 */

	// get_sections
	// Initialize a vector of Sections and return a pointer to client.
	//
	// Returns a vector of Section objects.
	PELIB_API std::unique_ptr<std::vector<Section>>
	PeParser::get_sections()
	{
		auto sections = std::make_unique<std::vector<Section>>();

		for (auto& s : Sections)
		{
			sections.get()->emplace_back(s);
		}

		return sections;
	}

	// get_section_headers
	// Initialize a vector of SectionHeaders and return pointer to client.
	//
	// Returns a vector of SectionHeader objects.
	PELIB_API std::unique_ptr<std::vector<SectionHeader>>
	PeParser::get_section_headers()
	{
		auto headers = std::make_unique<std::vector<SectionHeader>>();

		for (auto& s : Sections)
		{
			headers.get()->emplace_back(s.Header);
		}

		return headers;
	}

	// get_section_by_name
	// Get the section corresponding to specified name, if it exists.
	//
	// Arguments:
	//	name - ASCII string representation of section name
	//
	// Returns a pointer to initialized Section structure.
	PELIB_API std::unique_ptr<Section>
	PeParser::get_section_by_name(const std::string& name)
	{
		for (auto& s : Sections)
		{
			if (s.Name == name)
			{
				return std::make_unique<Section>(s);
			}
		}

		return nullptr;
	}

	// get_section_header_by_name
	// Get the section header corresponding to specified name, if it exists.
	//
	// Arguments
	//	name - ASCII string representation of section name
	//
	// Returns a pointer to initialized SectionHeader structure.
	PELIB_API std::unique_ptr<SectionHeader>
	PeParser::get_section_header_by_name(const std::string& name)
	{
		for (auto& s : Sections)
		{
			if (s.Name == name)
			{
				return std::make_unique<SectionHeader>(s.Header);
			}
		}

		return nullptr;
	}

	/* ----------------------------------------------------------------------------
	 *	PeParser: Internal Methods
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

		DosHeader.magic = pDosHeader->e_magic;
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

		FileHeader.Machine = header.Machine;
		FileHeader.NumberOfSections = header.NumberOfSections;
		FileHeader.TimeDateStamp = header.TimeDateStamp;
		FileHeader.PointerToSymbolTable = header.PointerToSymbolTable;
		FileHeader.NumberOfSymbols = header.NumberOfSymbols;
		FileHeader.SizeOfOptionalHeader = header.SizeOfOptionalHeader;
		FileHeader.Characteristics = header.Characteristics;
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

	// parse_data_directory
	// Parse the data directory metadata for all entries.
	//
	// Arguments:
	//	buffer - image file buffer
	void PeParser::parse_data_directory(FileBuffer& buffer)
	{
		// compute the offset to the first data directory entry
		auto base = buffer.get()
			+ DosHeader.e_lfanew
			+ sizeof(unsigned long)
			+ sizeof(IMAGE_FILE_HEADER)
			+ FileHeader.SizeOfOptionalHeader
			- sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

		// populate the internal data directory metadata
		for (auto i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
		{
			auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(base + sizeof(IMAGE_DATA_DIRECTORY) * i);
			DataDirectory[i].VirtualAddress = dir->VirtualAddress;
			DataDirectory[i].Size = dir->Size;
		}
	}

	// parse_section_headers
	// Parse the image section headers.
	//
	// Arguments:
	//	buffer - image file buffer
	void PeParser::parse_sections(FileBuffer& buffer)
	{
		// compute offset to first section header
		auto base = buffer.get()
			+ DosHeader.e_lfanew
			+ sizeof(unsigned long)
			+ sizeof(IMAGE_FILE_HEADER)
			+ FileHeader.SizeOfOptionalHeader;

		for (auto i = 0; i < FileHeader.NumberOfSections; ++i)
		{
			auto header = reinterpret_cast<PIMAGE_SECTION_HEADER>(base + sizeof(IMAGE_SECTION_HEADER) * i);

			Section section{ new unsigned char[header->SizeOfRawData], header->SizeOfRawData };

			// construct the section name
			for (auto i = 0; i < IMAGE_SIZEOF_SHORT_NAME; ++i)
			{
				auto c = header->Name[i];
				if ('\0' == c)
				{
					break;
				}

				section.Name.push_back(static_cast<char>(c));
			}

			// initialize section header data
			memcpy_s(section.Header.Name, IMAGE_SIZEOF_SHORT_NAME, header->Name, IMAGE_SIZEOF_SHORT_NAME);
			section.Header.VirtualSize = header->Misc.VirtualSize;
			section.Header.VirtualAddress = header->VirtualAddress;
			section.Header.SizeOfRawData = header->SizeOfRawData;
			section.Header.PointerToRawData = header->PointerToRawData;
			section.Header.PointerToRelocations = header->PointerToRelocations;
			section.Header.PointerToLinenumbers = header->PointerToLinenumbers;
			section.Header.NumberOfRelocations = header->NumberOfRelocations;
			section.Header.NumberOfLinenumbers = header->NumberOfLinenumbers;
			section.Header.Characteristics = header->Characteristics;

			// copy the section data to allocated buffer
			memcpy_s(
				section.Content.get(),
				header->SizeOfRawData,
				buffer.get() + header->PointerToRawData,
				header->SizeOfRawData
			);

			Sections.push_back(std::move(section));
		}
	}

	// parse_imports
	// Parse image imports.
	// 
	// Arguments:
	//	buffer - image file buffer
	void PeParser::parse_imports(FileBuffer& buffer)
	{
		// TODO
	}

	// parse_exports
	// Parse image exports.
	// 
	// Arguments:
	//	buffer - image file buffer
	void parse_exports(FileBuffer& buffer)
	{
		// TODO
	}

	/* ----------------------------------------------------------------------------
	 *	Exported Utility Functions
	 */

	// decode_machine
	// Return string representation of file header machine field.
	//
	// Returns string representation of image machine field.
	PELIB_API std::string
	decode_machine(unsigned short machine)
	{
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

	// decode_characteristics
	// Initialize a vector of strings representing the image characteristics.
	//
	// Returns vector of strings representing image characteristics.
	PELIB_API std::unique_ptr<std::vector<std::string>>
	decode_characteristics(unsigned short flags)
	{
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

	// decode_section_characteristics
	// Interpret the characteristics of a section header.
	// 
	// Arguments
	//	flags - 32-bit value representing section characteristics
	//
	// Returns a vector of strings representing characteristics present.
	PELIB_API std::unique_ptr<std::vector<std::string>>
	decode_section_characteristics(unsigned long flags)
	{
		auto characteristics = std::make_unique<std::vector<std::string>>();

		push_if_flag_set(characteristics, flags, IMAGE_SCN_TYPE_NO_PAD, "IMAGE_SCN_TYPE_NO_PAD");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_CNT_CODE, "IMAGE_SCN_CNT_CODE");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_CNT_INITIALIZED_DATA, "IMAGE_SCN_CNT_INITIALIZED_DATA");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_CNT_UNINITIALIZED_DATA, "IMAGE_SCN_CNT_UNINITIALIZED_DATA");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_LNK_OTHER, "IMAGE_SCN_LNK_OTHER");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_LNK_INFO, "IMAGE_SCN_LNK_INFO");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_LNK_REMOVE, "IMAGE_SCN_LNK_REMOVE");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_NO_DEFER_SPEC_EXC, "IMAGE_SCN_NO_DEFER_SPEC_EXC");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_GPREL, "IMAGE_SCN_GPREL");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_PURGEABLE, "IMAGE_SCN_MEM_PURGEABLE");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_LOCKED, "IMAGE_SCN_MEM_LOCKED");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_PRELOAD, "IMAGE_SCN_MEM_PRELOAD");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_1BYTES, "IMAGE_SCN_ALIGN_1BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_2BYTES, "IMAGE_SCN_ALIGN_2BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_4BYTES, "IMAGE_SCN_ALIGN_4BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_8BYTES, "IMAGE_SCN_ALIGN_8BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_16BYTES, "IMAGE_SCN_ALIGN_16BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_32BYTES, "IMAGE_SCN_ALIGN_32BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_64BYTES, "IMAGE_SCN_ALIGN_64BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_128BYTES, "IMAGE_SCN_ALIGN_128BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_256BYTES, "IMAGE_SCN_ALIGN_256BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_512BYTES, "IMAGE_SCN_ALIGN_512BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_1024BYTES, "IMAGE_SCN_ALIGN_1024BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_2048BYTES, "IMAGE_SCN_ALIGN_2048BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_4096BYTES, "IMAGE_SCN_ALIGN_4096BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_ALIGN_8192BYTES, "IMAGE_SCN_ALIGN_8192BYTES");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_LNK_NRELOC_OVFL, "IMAGE_SCN_LNK_NRELOC_OVFL");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_DISCARDABLE, "IMAGE_SCN_MEM_DISCARDABLE");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_NOT_CACHED, "IMAGE_SCN_MEM_NOT_CACHED");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_NOT_PAGED, "IMAGE_SCN_MEM_NOT_PAGED");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_SHARED, "IMAGE_SCN_MEM_SHARED");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_EXECUTE, "IMAGE_SCN_MEM_EXECUTE");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_READ, "IMAGE_SCN_MEM_READ");
		push_if_flag_set(characteristics, flags, IMAGE_SCN_MEM_WRITE, "IMAGE_SCN_MEM_WRITE");

		return characteristics;
	}

	/* ----------------------------------------------------------------------------
	 *	Internal Utility Functions
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
	inline void push_if_flag_set(
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

}

