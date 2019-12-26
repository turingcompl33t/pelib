// PeLib.h
// Portable Executable parsing library implementation.

#pragma once

#include <array>
#include <string>
#include <cstdio>
#include <memory>
#include <vector>

#include "Data.h"

#ifdef PELIB_EXPORTS
	#define PELIB_API __declspec(dllexport)
#else
	#define PELIB_API __declspec(dllimport)
#endif

namespace PeLib {

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

		PELIB_API std::unique_ptr<std::vector<Section>>       get_sections();
		PELIB_API std::unique_ptr<std::vector<SectionHeader>> get_section_headers();
		PELIB_API std::unique_ptr<Section>                    get_section_by_name(const std::string& name);
		PELIB_API std::unique_ptr<SectionHeader>              get_section_header_by_name(const std::string& name);

		// private (internal) methods
	private:
		bool is_valid_pe(FileBuffer& buffer);

		void parse_dos_header(FileBuffer& buffer);
		void parse_nt_headers(FileBuffer& buffer);
		void parse_file_header(FileBuffer& buffer);
		void parse_optional_header(FileBuffer& buffer);
		void parse_optional_header32(FileBuffer& buffer);
		void parse_optional_header64(FileBuffer& buffer);
		void parse_data_directory(FileBuffer& buffer);
		void parse_sections(FileBuffer& buffer);
		void parse_imports(FileBuffer& buffer);
		void parse_exports(FileBuffer& buffer);

		// data members
	private:
		std::string file_path;

		DosHeader      DosHeader;
		NtHeaders      NtHeaders;
		FileHeader     FileHeader;
		OptionalHeader OptionalHeader;

		std::array<DataDirectoryEntry, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> DataDirectory;

		std::vector<Section> Sections;
	};

	PELIB_API std::string                                decode_machine(unsigned short machine);
	PELIB_API std::unique_ptr<std::vector<std::string>>  decode_characteristics(unsigned short flags);
	PELIB_API std::unique_ptr<std::vector<std::string>>  decode_section_characteristics(unsigned long flags);
}

