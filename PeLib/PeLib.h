// PeLib.h
// Portable Executable parsing library implementation.

#pragma once

#include <string>
#include <cstdio>
#include <memory>
#include <vector>

#ifdef PELIB_EXPORTS
	#define PELIB_API __declspec(dllexport)
#else
	#define PELIB_API __declspec(dllimport)
#endif

#ifdef _DEBUG
	#define DbgPrint(x) printf("[PeLib] " x); puts("")
#else
	#define DbgPrint(x)
#endif

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

// top-level PE parser class
class PeParser
{

	// public (exported) methods
public:
	explicit PELIB_API PeParser(const std::string& file_path);
	PELIB_API ~PeParser();

	// disable copies
	PELIB_API PeParser(const PeParser& rhs) = delete;
	PELIB_API PeParser& operator=(const PeParser& rhs) = delete;

	// disable moves
	PELIB_API PeParser(PeParser&& rhs) = delete;
	PELIB_API PeParser& operator=(PeParser&& rhs) = delete;

	PELIB_API PeParseResult parse();

	PELIB_API std::string get_machine();
	PELIB_API std::unique_ptr<std::vector<std::string>> get_characteristics();

	// private (internal) methods
private:
	bool is_valid_pe(FileBuffer& buffer);

	void parse_dos_header(FileBuffer& buffer);
	void parse_nt_headers(FileBuffer& buffer);
	void parse_file_header(FileBuffer& buffer);
	void parse_optional_header(FileBuffer& buffer);
	void parse_optional_header32(FileBuffer& buffer);
	void parse_optional_header64(FileBuffer& buffer);

	// data members
private:
	std::string file_path;

	DosHeader_t      DosHeader;
	NtHeaders_t      NtHeaders;
	FileHeader_t     FileHeader;
	OptionalHeader_t OptionalHeader;
};

/* ----------------------------------------------------------------------------
 *	Utility Functions
 */

void push_if_flag_set(
	std::unique_ptr<std::vector<std::string>>& vec,
	unsigned short flags,
	unsigned short mask,
	std::string str
);




