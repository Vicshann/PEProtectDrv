#pragma once

#include "DrvDevice.h"
#include "DrvFormatPE.h"
//------------------------------------------------------------------------------
//---------------------------------------------------------------------------------
//                     COMPILE TIME STRING ENCRYPTION   [ lstrlen(ENCS("Hello World!")); ]
// Optimization must be turned ON to remove a HUGE portions of code (Macro expansion)
//---------------------------------------------------------------------------------
#define RESTRMAX 32
#define INFOXOR 0x5257424B
#define DOENCKEY(str,idx) (str[idx])
#define EKEY2 DOENCKEY(__TIME__,6)
#define EKEY1 DOENCKEY(__TIME__,7)
#define EKEY  ((EKEY1) ^ (EKEY2))

#define ESB1(str,key,idx) ((BYTE)((idx < sizeof(str))?((((str)[(idx)] ^ (BYTE)(key)) ^ (idx))):(0)))
#define ESB4(str,key,idx) ((DWORD)((ESB1(str,key,(idx*4))<<8)|(ESB1(str,key,((idx*4)+1))<<24)|(ESB1(str,key,((idx*4)+2)))|(ESB1(str,key,((idx*4)+3))<<16)))
#define SINF(str,key)     ((DWORD)((sizeof(str)|((key)<<24)) ^ INFOXOR))   
#define ESB(str,idx)      ((DWORD)ESB4(str,EKEY,idx)) 

// Try to construct this macro dynamically
//#define ENCS(str)  SDecryptRtStr<8>(SINF(str,EKEY), ESB(str,0), ESB(str,1), ESB(str,2), ESB(str,3), ESB(str,4), ESB(str,5), ESB(str,6), ESB(str,7))  // 32  
#define ENCSN(nam,str)  SDecryptRtStr<8> nam (SINF(str,EKEY), ESB(str,0), ESB(str,1), ESB(str,2), ESB(str,3), ESB(str,4), ESB(str,5), ESB(str,6), ESB(str,7))  // 32  
#define ENCS(str) ENCSN( ,str)
//#define ENCS(str) (str)

template<int i> class SDecryptRtStr  
{    // No another vars here - some optimization bug.
 WORD Size;    // Including terminating Zero
 union
  {
   DWORD dval[i];
   char  cval[i*sizeof(DWORD)];
  };
public:
 __declspec(noinline) SDecryptRtStr(DWORD info, ...)
 {
  info ^= INFOXOR;
  DWORD Key  = (info >> 24);
  DWORD bLen = (info & 0xFF);
  DWORD VXor = (Key << 24)|(Key << 16)|(Key << 8)|Key;  
  if(bLen > (i*sizeof(DWORD)))bLen = (i*sizeof(DWORD));
  UINT  wLen = (bLen/sizeof(DWORD))+(bool)(bLen%sizeof(DWORD));  // Always has a Zero DWORD at end
  ULONG_PTR* args = reinterpret_cast<ULONG_PTR*>(&info);
  args++;   
  for(UINT ctr=0;ctr < wLen;ctr++)
   {
    DWORD data = args[ctr];  // reinterpret_cast<PUINT>(args)[ctr];   // On x64 it is 8 bytes
    DWORD inx  = (ctr*4);
    DWORD xval = (((inx+1) << 24)|((inx+3) << 16)|((inx+0) << 8)|(inx+2));
    data = (data ^ VXor) ^ xval;
    data = ((data << 16)&0x00FF0000)|((data >> 8)&0x000000FF)|((data << 8)&0xFF000000)|((data >> 16)&0x0000FF00);
    this->dval[ctr] = data;  
   } 
  cval[bLen-1] = 0;
  this->Size = bLen;
 } 
 //------------------------ 
 ~SDecryptRtStr()
 {
  UINT wLen = (this->Size/sizeof(DWORD))+(bool)(this->Size%sizeof(DWORD));
  for(UINT ctr=0;ctr<wLen;ctr++)this->dval[ctr] = 0;
 }      
 operator const char*() const {return reinterpret_cast<const char*>(&this->cval);}
 operator LPSTR() const {return (LPSTR)&this->cval;}
 operator const int()   const {return this->Size;}
};
//---------------------------------------------------------------------------------
enum MEMORY_INFORMATION_CLASS {MemoryBasicInformation=0};

enum SYSTEM_INFORMATION_CLASS {SystemModuleInformation=11};

enum FIRMWARE_REENTRY {
    HalHaltRoutine,
    HalPowerDownRoutine,
    HalRestartRoutine,
    HalRebootRoutine,
    HalInteractiveModeRoutine,
    HalMaximumRoutine};

enum SHUTDOWN_ACTION {  
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff};

typedef struct _MEMORY_BASIC_INFORMATION 
{  
 PVOID  BaseAddress;  
 PVOID  AllocationBase;  
 DWORD  AllocationProtect;  
 SIZE_T RegionSize;  
 DWORD  State;  
 DWORD  Protect;  
 DWORD  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

VOID HalReturnToFirmware(IN FIRMWARE_REENTRY Routine);
NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION Action);
NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, ULONG Length, PULONG ResultLength);
VOID KeInitializeApc(PKAPC Apc, PKTHREAD Thread, UCHAR StateIndex, PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine, PKNORMAL_ROUTINE NormalRoutine, KPROCESSOR_MODE ApcMode, PVOID NormalContext);
BOOLEAN KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);
//---------------------------------------------------------------------------------


