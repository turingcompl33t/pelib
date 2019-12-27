// Utility.h
// Exported utility function definitions.

#pragma once

#include <memory>
#include <vector>
#include <string>

#include "Environment.h"

namespace PeLib {

	PELIB_API std::string                                
	decode_machine(unsigned short machine);

	PELIB_API std::unique_ptr<std::vector<std::string>>  
	decode_characteristics(unsigned short flags);

	PELIB_API std::unique_ptr<std::vector<std::string>> 
	decode_section_characteristics(unsigned long flags);
}

