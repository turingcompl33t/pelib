// Environment.h
// Build environment definitions for all project headers.

#pragma once

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
