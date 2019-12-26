// Data.h
// Data structure definitions.

#pragma once

#include <windows.h>
#include <memory>

using FileBuffer = std::unique_ptr<unsigned char[]>;

enum class PeParseResult
{
	ResultSuccess,
	ResultGeneralFailure,
	ResultFileInaccessible,
	ResultFileReadFailed,
	ResultFileMalformed
};

typedef struct DosHeader
{
	long magic;
	long e_lfanew;
} DosHeader_t;

typedef struct NtHeaders
{
	unsigned long Signature;
} NtHeaders_t;

typedef struct FileHeader
{
	unsigned short Machine;
	unsigned short NumberOfSections;
	unsigned long  TimeDateStamp;
	unsigned long  PointerToSymbolTable;
	unsigned long  NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
} FileHeader_t;

typedef struct OptionalHeader
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
} OptionalHeader_t;

typedef struct DataDirectoryEntry
{
	unsigned long VirtualAddress;
	unsigned long Size;
} DataDirectoryEntry_t;

typedef struct SectionHeader
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

	SectionHeader(
		unsigned char Name_arg[],
		unsigned long VirtualSize,
		unsigned long VirtualAddress,
		unsigned long SizeOfRawData,
		unsigned long PointerToRawData,
		unsigned long PointerToRelocations,
		unsigned long PointerToLinenumbers,
		unsigned short NumberOfRelocations,
		unsigned short NumberOfLinenumbers,
		unsigned long Characteristics)
		: VirtualSize{ VirtualSize },
		VirtualAddress{ VirtualAddress },
		SizeOfRawData{ SizeOfRawData },
		PointerToRawData{ PointerToRawData },
		PointerToRelocations{ PointerToRelocations },
		PointerToLinenumbers{ PointerToLinenumbers },
		NumberOfRelocations{ NumberOfRelocations },
		NumberOfLinenumbers{ NumberOfLinenumbers },
		Characteristics{ Characteristics }
	{
		memcpy_s(
			reinterpret_cast<void*>(Name),
			IMAGE_SIZEOF_SHORT_NAME,
			reinterpret_cast<void*>(Name_arg),
			IMAGE_SIZEOF_SHORT_NAME
		);
	}
} SectionHeader_t;
