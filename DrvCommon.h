
#pragma once

//void realdprintf (char const *file, int line, char const *fmt, ...){}
//#define dprintf(...) realdprintf(__FILE__, __LINE__, __VA_ARGS__)
// EXAMPLE: dprintf("d",2,"t",2,7,"hello");

// If need print a string by ptr, use LOGMSG("%s",Ptr);
#define LOGMSG(msg,...) DbgPrint
#define LOGFMSG(msg,...) DbgPrint(__FUNCTION__ ": " msg "\n",__VA_ARGS__)

#if _DEBUG
#define DBGOUT DbgPrint 
#define DBGMSG LOGFMSG 
#else
#pragma warning(disable:4002)
#define DBGOUT(arg)
#define DBGMSG(arg)
#endif

#pragma warning(disable:4201)
#pragma warning(disable:4214)
#pragma warning(disable:4115)
#pragma warning(disable:4324) // x64: structure was padded due to __declspec(align())


#if defined(__cplusplus)
extern "C" {
#endif

#include <ntddk.h>
#include <basetsd.h>
#include <windef.h>

#pragma function(memset)
#pragma function(memcpy)

#if defined (__cplusplus)
}
#endif


