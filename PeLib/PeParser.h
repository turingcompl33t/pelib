// PeParser.h
// Class definition for Portable Executable parser.

#pragma once

#include <vector>
#include <string>
#include <memory>

#include "Data.h"
#include "Environment.h"

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

		PELIB_API std::unique_ptr<std::vector<Import>>        get_imports();
		PELIB_API std::unique_ptr<std::vector<Import>>        get_imports_from_source(std::string name);

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

		unsigned long rva_to_offset(unsigned long va);

		// data members
	private:
		std::string file_path;

		DosHeader      DosHeader;
		NtHeaders      NtHeaders;
		FileHeader     FileHeader;
		OptionalHeader OptionalHeader;

		std::array<DataDirectoryEntry, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> DataDirectory;

		std::vector<Section> Sections;
		std::vector<Import>  Imports;
	};


}
