#pragma once

#include "DrvCommon.h" // place it before <ntddk.h> to avoid warnings
#include "DrvFormatPE.h"
#include "DrvKernelImport.h"
//------------------------------------------------------------------------------
#define MAXFUNCPCI 8  // See PCI spec
#define MAXDEVPCI  8  // Limit is 32 but 8 must be enough

// For old DDK (Need DDK update)
#ifdef _AMD64_
#ifndef KeQuerySystemTime
#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64
#define SharedSystemTime (KI_USER_SHARED_DATA + 0x14)
#define KeQuerySystemTime(CurrentCount) *((PULONG64)(CurrentCount)) = *((volatile ULONG64 *)(SharedSystemTime))
#endif
#endif 

//------------------------------------------------------------------------------
// Returned to User after requests of Memory allocation or Device IO mapping
struct TMemDescr
{
 UINT  Length;
 PVOID UserVA;
 PVOID SystemVA;
 PVOID HardAddr;  // Hardware Address of first page 
};
//------------------------------------------------------------------------------
union IoCtrlCode
{
 DWORD dwControlCode;
 struct
  {
   DWORD TransferType   : 2;
   DWORD FunctionCode   : 12;
   DWORD RequiredAccess : 2;
   DWORD DeviceType     : 16;
  };
 IoCtrlCode(unsigned int Code=0){this->dwControlCode = Code;}
 IoCtrlCode(int TransType, int FuncCode, int ReqAccess, int DevType)
  {
   this->TransferType   = TransType;
   this->FunctionCode   = FuncCode;
   this->RequiredAccess = ReqAccess;
   this->DeviceType     = DevType;
  }
};
//------------------------------------------------------------------------------
// Can be returned as a simple DWORD
union PCIDevAddr
{
 struct
  {
   DWORD BusNumber      : 8;  // Max 256 ?
   DWORD DeviceNumber   : 5;  // As specified in 'PCI_SLOT_NUMBER' Max 32
   DWORD FunctionNumber : 3;  // As specified in 'PCI_SLOT_NUMBER' Max 8
   DWORD FunctionsMask  : 8;  // D0=f0,D1=f1,...,D7=f8 ; 1 - Function are present
   DWORD TotalFunctions : 8;  // Total functions in device
  };
 DWORD dwDeviceAddr;

 PCIDevAddr(DWORD DevAddr=0){this->dwDeviceAddr = DevAddr;}
 PCIDevAddr(DWORD BusNum,DWORD DevNum,DWORD FuncNum,DWORD FuncMask=0,DWORD TotalFuncs=0)
  {
   this->BusNumber      = BusNum;
   this->DeviceNumber   = DevNum;
   this->FunctionNumber = FuncNum;
   this->FunctionsMask  = FuncMask;
   this->TotalFunctions = TotalFuncs;
  }
 DWORD MakeSlotPCI(void)
  {
   PCI_SLOT_NUMBER DeviceSlot;
   DeviceSlot.u.bits.Reserved       = 0;
   DeviceSlot.u.bits.DeviceNumber   = this->DeviceNumber;
   DeviceSlot.u.bits.FunctionNumber = this->FunctionNumber;      
   return DeviceSlot.u.AsULONG;
  }
};
//==============================================================================



//==============================================================================
//
// Private flags for loader data table entries
//
#define LDRP_STATIC_LINK                0x00000002
#define LDRP_IMAGE_DLL                  0x00000004
#define LDRP_LOAD_IN_PROGRESS           0x00001000
#define LDRP_UNLOAD_IN_PROGRESS         0x00002000
#define LDRP_ENTRY_PROCESSED            0x00004000
#define LDRP_ENTRY_INSERTED             0x00008000
#define LDRP_CURRENT_LOAD               0x00010000
#define LDRP_FAILED_BUILTIN_LOAD        0x00020000
#define LDRP_DONT_CALL_FOR_THREADS      0x00040000
#define LDRP_PROCESS_ATTACH_CALLED      0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED       0x00100000
#define LDRP_IMAGE_NOT_AT_BASE          0x00200000
#define LDRP_COR_IMAGE                  0x00400000
#define LDRP_COR_OWNS_UNMAP             0x00800000
#define LDRP_SYSTEM_MAPPED              0x01000000
#define LDRP_IMAGE_VERIFYING            0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL       0x04000000
#define LDRP_ENTRY_NATIVE               0x08000000
#define LDRP_REDIRECTED                 0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO       0x20000000
#define LDRP_MM_LOADED                  0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED  0x80000000
//==============================================================================
template<typename T> struct LDR_LIST_ENTRY
{
 T *Next; 
 T *Prev;  
}; 
//==============================================================================
//
// Loader Data Table Entry   // x64 alignment must be 8
//
struct LDR_MODULE
{
 PVOID ModuleBase;
 PVOID EntryPoint;
 ULONG SizeOfImage;         
 UNICODE_STRING FullModuleName;
 UNICODE_STRING BaseModuleName;
 ULONG Flags;  // see LDRP_***
 WORD  LoadCount;
 WORD  TlsIndex;
 union
  {
   LDR_LIST_ENTRY<PVOID> HashLinks; // UNFINISHED!!! in LdrpHashTable[]        // !!!!!!!!!!!!!!!!!!!!!!!! Process this, when removing a Dll !!!!!!!!!!!!!!!!!!!!!!!!!
   struct
	{
	 PVOID SectionPointer; // for kernel mode and session images only.
	 ULONG CheckSum;       // for kernel mode images only.
	};
  };
 union
  {
   ULONG TimeDateStamp;
   PVOID LoadedImports; // for kernel mode images only.
  };
 PVOID EntryPointActivationContext;    // Rare! ?????
 PVOID PatchInformation;               // Rare! ?????
};
//==============================================================================
struct LDR_MODULE_ENTRY_IO   // Initialization order
{
 LDR_LIST_ENTRY<LDR_MODULE_ENTRY_IO> InInitializationOrderLinks;
 LDR_MODULE Module;
};
//---------------------------------------------------------------------------
struct LDR_MODULE_ENTRY_MO   // Memory order
{
 LDR_LIST_ENTRY<LDR_MODULE_ENTRY_MO> InMemoryOrderLinks;
 LDR_LIST_ENTRY<LDR_MODULE_ENTRY_IO> InInitializationOrderLinks;
 LDR_MODULE Module;
};
//---------------------------------------------------------------------------
struct LDR_MODULE_ENTRY_LO   // Load order
{
 LDR_LIST_ENTRY<LDR_MODULE_ENTRY_LO> InLoadOrderLinks;
 LDR_LIST_ENTRY<LDR_MODULE_ENTRY_MO> InMemoryOrderLinks;
 LDR_LIST_ENTRY<LDR_MODULE_ENTRY_IO> InInitializationOrderLinks;
 LDR_MODULE Module;
};
//==============================================================================
struct SYSTEM_MODULE_ENTRY   // SystemModuleInformation (11)
{
 ULONG_PTR Unknown[2];  // x64/x32
 PVOID  Base;
 ULONG  Size;
 ULONG  Flags;
 USHORT Index;
 USHORT NameLength;
 USHORT LoadCount;
 USHORT PathLength;
 CHAR   ModuleFullPath[256];
};

struct SYSTEM_MODULE_INFORMATION
{
 ULONG Count;
 SYSTEM_MODULE_ENTRY Modules[0];
};
//==============================================================================



void* _cdecl operator new(size_t size );
void  _cdecl operator delete(PVOID ptr);

//int        _stdcall MapBusIoToUserSpace(INTERFACE_TYPE Bus,UINT BusNumber,UINT BusAddress,UINT BusIoLength, PMDL *DevIoMdl, PVOID *DevIoSysBase, PVOID *DevIoUsrBase);  
//int        _stdcall UnMapBusIoFromUserSpace(UINT BusIoLength, PMDL DevIoMdl, PVOID DevIoSysBase, PVOID DevIoUsrBase);  
//int        _stdcall AllocContigMemToUserSpace(UINT Length, PMDL *MemMdl, PVOID *MemSysBase, PVOID *MemUsrBase);
//int        _stdcall FreeContigMemFromUserSpace(UINT Length, PMDL MemMdl, PVOID MemSysBase, PVOID MemUsrBase);
//int        _stdcall GetDeviceDataPCI(PCIDevAddr DeviceAddr, PVOID Buffer, UINT Length, UINT Offset);
//int        _stdcall GetDeviceStatusPCI(PCIDevAddr DeviceAddr);
//PCIDevAddr _stdcall FindDevicePCI(DWORD VendorID, DWORD DeviceID, UINT CardIndex);
//UINT       _stdcall CheckMemoryPresence(PVOID Address, UINT Length);


NTSTATUS _stdcall SendIrpSynchronously(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
//UINT  _stdcall EnumerateKernelModules(PDRIVER_OBJECT DriverObject);
CHAR  _stdcall CharCaseUpper(CHAR Chr);
BOOL  _stdcall IsCharsEqualIC(CHAR ChrA, CHAR ChrB);
PVOID _stdcall GetCurrentModule(void);
//PVOID _stdcall ProcessGetModuleBase(PCHAR ModuleName);
PVOID _stdcall KernelGetModuleBase(PDRIVER_OBJECT DriverObject, PCHAR ModuleName);
UINT  _stdcall GetServiceIndexOffset(DWORD SrvIndex, PVOID SrvAddress);


NTSTATUS DeclareCustomDevice(PDRIVER_OBJECT DriverObject, UINT ExtSize, BOOL MakeName, BOOL MakeSymLink);
NTSTATUS DestroyCustomDevice(PDEVICE_OBJECT DeviceObject);
NTSTATUS GetDeviceNameStr(PUNICODE_STRING Str);
NTSTATUS GetSymLinkNameStr(PUNICODE_STRING Str);
BOOL IsModuleOnPath(PUNICODE_STRING ModPath, PUNICODE_STRING FullPath);
BOOL IsModuleOnPathNtdll(PUNICODE_STRING FullPath);
ULONG_PTR GetKernelBase(PDRIVER_OBJECT DriverObject);
PVOID GetProcNtdllA(PVOID ModBase);
PVOID GetProcNtdllB(PVOID ModBase);
PVOID GetProcNtoskrnlA(void);
PVOID GetProcNtoskrnlB(void);
void  LogResetMessage(UINT FCtr);

BOOL IsUserAddressValid(PVOID Address);
BOOL IsModuleFullyMapped(PVOID Address, SIZE_T Size);

//------------------------------------------------------------------------------


