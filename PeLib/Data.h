// Data.h
// Data structure definitions.

#pragma once

#include <windows.h>
#include <memory>

namespace PeLib {

	using FileBuffer = std::unique_ptr<unsigned char[]>;

	enum class PeParseResult
	{
		ResultSuccess,
		ResultGeneralFailure,
		ResultFileInaccessible,
		ResultFileReadFailed,
		ResultFileMalformed
	};

	struct DosHeader
	{
		long magic;
		long e_lfanew;
	};

	struct NtHeaders
	{
		unsigned long Signature;
	};

	struct FileHeader
	{
		unsigned short Machine;
		unsigned short NumberOfSections;
		unsigned long  TimeDateStamp;
		unsigned long  PointerToSymbolTable;
		unsigned long  NumberOfSymbols;
		unsigned short SizeOfOptionalHeader;
		unsigned short Characteristics;
	};

	struct OptionalHeader
	{
		unsigned short      Magic;
		unsigned char       MajorLinkerVersion;
		unsigned char       MinorLinkerVersion;
		unsigned long       SizeOfCode;
		unsigned long       SizeOfInitializedData;
		unsigned long       SizeOfUninitializedData;
		unsigned long       AddressOfEntryPoint;
		unsigned long       BaseOfCode;
		unsigned long long  ImageBase;
		unsigned long       SectionAlignment;
		unsigned long       FileAlignment;
		unsigned short      MajorOperatingSystemVersion;
		unsigned short      MinorOperatingSystemVersion;
		unsigned short      MajorImageVersion;
		unsigned short      MinorImageVersion;
		unsigned short      MajorSubsystemVersion;
		unsigned short      MinorSubsystemVersion;
		unsigned long       Win32VersionValue;
		unsigned long       SizeOfImage;
		unsigned long       SizeOfHeaders;
		unsigned long       CheckSum;
		unsigned short      Subsystem;
		unsigned short      DllCharacteristics;
		unsigned long long  SizeOfStackReserve;
		unsigned long long  SizeOfStackCommit;
		unsigned long long  SizeOfHeapReserve;
		unsigned long long  SizeOfHeapCommit;
		unsigned long       LoaderFlags;
		unsigned long       NumberOfRvaAndSizes;
	};

	struct DataDirectoryEntry
	{
		unsigned long VirtualAddress;
		unsigned long Size;
	};

	struct SectionHeader
	{
		unsigned char  Name[IMAGE_SIZEOF_SHORT_NAME];
		unsigned long  VirtualSize;
		unsigned long  VirtualAddress;
		unsigned long  SizeOfRawData;
		unsigned long  PointerToRawData;
		unsigned long  PointerToRelocations;
		unsigned long  PointerToLinenumbers;
		unsigned short NumberOfRelocations;
		unsigned short NumberOfLinenumbers;
		unsigned long  Characteristics;

		SectionHeader() = default;

		SectionHeader(const SectionHeader& other)
			: VirtualSize{ other.VirtualSize },
			VirtualAddress{ other.VirtualAddress },
			SizeOfRawData{ other.SizeOfRawData },
			PointerToRawData{ other.PointerToRawData },
			PointerToRelocations{ other.PointerToRelocations },
			PointerToLinenumbers{ other.PointerToLinenumbers },
			NumberOfRelocations{ other.NumberOfRelocations },
			NumberOfLinenumbers{ other.NumberOfLinenumbers },
			Characteristics{ other.Characteristics }
		{
			memcpy_s(
				Name,
				IMAGE_SIZEOF_SHORT_NAME,
				other.Name,
				IMAGE_SIZEOF_SHORT_NAME
			);
		}
	};

	struct Section
	{
		std::string                      Name;
		SectionHeader                    Header;
		std::shared_ptr<unsigned char[]> Content;
		size_t                           ContentSize;

		// invoked during parsing
		Section(unsigned char content[], size_t content_size)
			: Header{}, 
			Name{},
			Content{ std::move(content) },
			ContentSize{ content_size }
		{}

		// invoked during on-demand query
		Section(const Section& other)
			: Name{ other.Name }, 
			Header{ other.Header },
			Content{ other.Content },
			ContentSize{ other.ContentSize }
		{}
	};
}
