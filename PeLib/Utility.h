// Utility.h
// Internal header for private function declarations.

#pragma once

#include <memory>
#include <vector>
#include <string>

#ifdef _DEBUG
	#define DbgPrint(x) printf("[PeLib] " x); puts("")
#else
	#define DbgPrint(x)
#endif

namespace PeLib {

	inline void push_if_flag_set(
		std::unique_ptr<std::vector<std::string>>& vec,
		unsigned short flags,
		unsigned short mask,
		std::string str
	);
}

