// Internal.h
// Internal (non-exported) utility function definitions.

#pragma once

#include <vector>
#include <string>
#include <memory>

namespace PeLib {
	inline void push_if_flag_set(
		std::unique_ptr<std::vector<std::string>>& vec,
		unsigned short flags,
		unsigned short mask,
		std::string str
	);
}
