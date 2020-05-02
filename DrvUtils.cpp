//==============================================================================
#include "DrvUtils.h"

//------------------------------------------------------------------------------
void * _cdecl operator new(size_t size )
{
 return ExAllocatePoolWithTag(NonPagedPool, (ULONG) size, 'KLBM'); 
}
//------------------------------------------------------------------------------
void _cdecl operator delete(PVOID ptr)
{
 ExFreePool(ptr);
}
//------------------------------------------------------------------------------
NTSTATUS CompleteIrp( PIRP Irp, NTSTATUS status, ULONG info)
{
 Irp->IoStatus.Status = status;
 Irp->IoStatus.Information = info;
 IoCompleteRequest(Irp,IO_NO_INCREMENT);
 return status;
}
//------------------------------------------------------------------------------
/*PCIDevAddr _stdcall FindDevicePCI(DWORD VendorID, DWORD DeviceID, UINT CardIndex)
{
 struct{DWORD VenID:16;DWORD DevID:16;}PciDevIDs;
 UINT       Result; 
 PCIDevAddr DeviceAddr;

 DBGOUT("'%s': Searching for device: VendorID=%04X, DeviceID=%04X, CardIndex=%u",__FUNCTION__,VendorID,DeviceID,CardIndex);
 DeviceAddr.dwDeviceAddr = 0;
 for(int BusNumber = 0;BusNumber < 256;BusNumber++)
  {
   DeviceAddr.BusNumber = BusNumber;
   for(int DeviceNumber=0,CardCount=0,FuncCount,FuncMask;DeviceNumber < PCI_MAX_DEVICES;DeviceNumber++)
    {
     FuncMask  = 0;
     FuncCount = 0;
     DeviceAddr.DeviceNumber = DeviceNumber;
     for(int FuncNumber = 0;FuncNumber < PCI_MAX_FUNCTION;FuncNumber++)
      {
       DeviceAddr.FunctionNumber = FuncNumber;
       Result      = HalGetBusDataByOffset(PCIConfiguration,DeviceAddr.BusNumber,DeviceAddr.MakeSlotPCI(),&PciDevIDs,0,sizeof(DWORD));
       if(Result  == 0){DeviceNumber=PCI_MAX_DEVICES;break;} // No devices on this BUS
       if((Result == 2)&&(PciDevIDs.VenID==PCI_INVALID_VENDORID))continue; // Device\Function does not exist
       FuncCount++;
       FuncMask |= (1 << FuncNumber);
       if((PciDevIDs.VenID == VendorID) && (PciDevIDs.DevID == DeviceID) && !DeviceAddr.TotalFunctions)
        {
         if(CardCount == CardIndex)
          {
           DeviceAddr.FunctionsMask  = FuncNumber; // Use as temporary
           DeviceAddr.TotalFunctions = 1;          // Use as flag
          }
           else CardCount++;
        }
      }
     if(DeviceAddr.TotalFunctions)
      {
       DeviceAddr.FunctionNumber = DeviceAddr.FunctionsMask;
       DeviceAddr.FunctionsMask  = FuncMask;
       DeviceAddr.TotalFunctions = FuncCount;
       DBGOUT("'%s': Requested device is found: BusNumber=%u, DeviceNumber=%u, FunctionNumber=%u",__FUNCTION__,DeviceAddr.BusNumber,DeviceAddr.DeviceNumber,DeviceAddr.FunctionNumber);
       return DeviceAddr;
      }
    }  
  }
 DBGOUT("'%s': Requested device is NOT found!",__FUNCTION__);
 DeviceAddr.dwDeviceAddr = 0;  // A Specified device do not found!    
 return DeviceAddr;     
} */
//------------------------------------------------------------------------------
/*int _stdcall GetDeviceStatusPCI(PCIDevAddr DeviceAddr)
{
 WORD VendorID;
 UINT Result = HalGetBusDataByOffset(PCIConfiguration,DeviceAddr.BusNumber,DeviceAddr.MakeSlotPCI(),&VendorID,0,sizeof(WORD));
 if(Result  == 0)return -1;   // Bus Does Not Exist
 if((Result == 2)&&(VendorID==PCI_INVALID_VENDORID))return -2;  // Device\Function Do Not Exist
 return 0;
} */
//------------------------------------------------------------------------------
/*int _stdcall GetDeviceDataPCI(PCIDevAddr DeviceAddr, PVOID Buffer, UINT Length, UINT Offset)
{
 UINT Result = GetDeviceStatusPCI(DeviceAddr); // Time consuming
 if(Result)return Result;
 if(Offset > 255)Offset = 0;
 if((Offset+Length) > 256)Length = (256-Offset);
 return HalGetBusDataByOffset(PCIConfiguration,DeviceAddr.BusNumber,DeviceAddr.MakeSlotPCI(),Buffer,Offset,Length);
}  */
//------------------------------------------------------------------------------
// BusIoLength - If = 0, use full IO range from device
// 'MapBusIoToUserSpace': BusAddress=FF000000[16777216(four functions?)], BusIoLength=00400000[4194304]
/*int _stdcall MapBusIoToUserSpace(INTERFACE_TYPE Bus,UINT BusNumber,UINT BusAddress,UINT BusIoLength, PMDL *DevIoMdl, PVOID *DevIoSysBase, PVOID *DevIoUsrBase)  
{            
 __try
  {
   DWORD AddrSpace            = 0x00; // Memory space
   PHYSICAL_ADDRESS IoAddress = {BusAddress};    // Must set a 'Quad' part
   DBGOUT("'%s': BusAddress=%08X, BusIoLength=%08X",__FUNCTION__,BusAddress,BusIoLength);
   if(HalTranslateBusAddress(Bus,BusNumber,IoAddress,&AddrSpace,&IoAddress))
    {
     (*DevIoSysBase) = MmMapIoSpace(IoAddress,BusIoLength,MmNonCached);
     (*DevIoMdl)     = IoAllocateMdl((*DevIoSysBase),BusIoLength,FALSE,FALSE,NULL); // WHAT PAGES IS THERE NOW? (MDL Flags=0x0008 [MDL_ALLOCATED_FIXED_SIZE])
     DBGOUT("'%s': DevIoSysBase=%08X, DevIoMdl=%08X",__FUNCTION__,(*DevIoSysBase),(*DevIoMdl));
     MmBuildMdlForNonPagedPool((*DevIoMdl));  // After this MDL pages will represent a device`s IO space, and 'MappedSystemVa' has also changed. (MDL Flags=0x080C [MDL_IO_SPACE|MDL_SOURCE_IS_NONPAGED_POOL|MDL_ALLOCATED_FIXED_SIZE])
     DBGOUT("'%s': MDL: Flags=%04X, MappedSystemVa=%08X, StartVa=%08X, ByteCount=%08X",__FUNCTION__,(*DevIoMdl)->MdlFlags,(*DevIoMdl)->MappedSystemVa,(*DevIoMdl)->StartVa,(*DevIoMdl)->ByteCount);
     (*DevIoUsrBase) = MmMapLockedPagesSpecifyCache((*DevIoMdl),UserMode,MmNonCached,NULL,FALSE,HighPagePriority);
     DBGOUT("'%s': IO Space mapped into User Address: %08X",__FUNCTION__,(*DevIoUsrBase));
    }
     else {DBGOUT("'%s': Failed to translate device`s bus address!",__FUNCTION__);return -1;}
  }__except(EXCEPTION_EXECUTE_HANDLER)
    {
     DBGOUT("'%s': Raised an exception!",__FUNCTION__);
     MmUnmapIoSpace((*DevIoSysBase),BusIoLength);
     IoFreeMdl((*DevIoMdl));
     (*DevIoMdl)     = NULL;
     (*DevIoSysBase) = NULL;
     (*DevIoUsrBase) = NULL;
     return -2;       
    }
 DBGOUT("'%s': Success.",__FUNCTION__);   
 return 0;
}  */
//------------------------------------------------------------------------------
/*int _stdcall UnMapBusIoFromUserSpace(UINT BusIoLength, PMDL DevIoMdl, PVOID DevIoSysBase, PVOID DevIoUsrBase)  
{            
 __try      
  {
   DBGOUT("'%s': BusIoLength=%08X, DevIoSysBase=%08X, DevIoUsrBase=%08X",__FUNCTION__,BusIoLength,DevIoSysBase,DevIoUsrBase);
   MmUnmapLockedPages(DevIoUsrBase,DevIoMdl);
   MmUnmapIoSpace(DevIoSysBase,BusIoLength);
   IoFreeMdl(DevIoMdl);
  }__except(EXCEPTION_EXECUTE_HANDLER){DBGOUT("'%s': Raised an exception!",__FUNCTION__);return -1;}
 DBGOUT("'%s': Success.",__FUNCTION__);  
 return 0;
}  */
//------------------------------------------------------------------------------
/*UINT _stdcall CheckMemoryPresence(PVOID Address, UINT Length)
{
 UINT BCount = 0;
 UINT AShift = ((UINT)Address) & 0x00000FFF;
 Length     += AShift;
 UINT LShift = (Length & 0xFFFFF000)+(0x1000*((bool)(Length & 0x00000FFF))); 
 Length     += LShift;
 Address     = (PVOID)(((UINT)Address) & 0xFFFFF000);
 while((BCount < Length)&&MmIsAddressValid(&((PBYTE)Address)[BCount]))BCount += 0x1000; // 4K pages
 return (BCount)?(BCount-(AShift+LShift)):(0);
}  */
//------------------------------------------------------------------------------
/*int _stdcall AllocContigMemToUserSpace(UINT Length, PMDL *MemMdl, PVOID *MemSysBase, PVOID *MemUsrBase)
{
 PHYSICAL_ADDRESS pha;
 pha.LowPart  = -1;
 pha.HighPart = 0; // No a devices with 64 bit support?
 if(!((*MemSysBase) = MmAllocateContiguousMemory(Length,pha)))return 1;
 (*MemMdl) = IoAllocateMdl((*MemSysBase),Length,FALSE,FALSE,NULL); // WHAT PAGES IS THERE NOW? (MDL Flags=0x0008 [MDL_ALLOCATED_FIXED_SIZE])
 DBGOUT("'%s': MemSysBase=%08X, MemMdl=%08X",__FUNCTION__,(*MemSysBase),(*MemMdl));
 MmBuildMdlForNonPagedPool((*MemMdl)); // Use 'MmProbeAndLockPages' instead to workaround of some system error? 
 DBGOUT("'%s': MDL: Flags=%04X, MappedSystemVa=%08X, StartVa=%08X, ByteCount=%08X",__FUNCTION__,(*MemMdl)->MdlFlags,(*MemMdl)->MappedSystemVa,(*MemMdl)->StartVa,(*MemMdl)->ByteCount);
 (*MemUsrBase) = MmMapLockedPagesSpecifyCache((*MemMdl),UserMode,MmNonCached,NULL,FALSE,HighPagePriority);
 DBGOUT("'%s': Memory mapped into User Address: %08X",__FUNCTION__,(*MemUsrBase));    
 return ((*MemUsrBase))?(0):(-1);
}  */
//------------------------------------------------------------------------------
/*int _stdcall FreeContigMemFromUserSpace(UINT Length, PMDL MemMdl, PVOID MemSysBase, PVOID MemUsrBase)
{
 __try
  {
   DBGMSG("MemSysBase=%08X, MemUsrBase=%08X, MemMdl=%08X",MemSysBase,MemUsrBase,MemMdl);
   if(MemUsrBase)MmUnmapLockedPages(MemUsrBase,MemMdl);
   if(MemMdl)IoFreeMdl(MemMdl);
   if(MemSysBase)MmFreeContiguousMemory(MemSysBase);
  }__except(EXCEPTION_EXECUTE_HANDLER){DBGMSG("Raised an exception!");return -1;}
 DBGMSG("Success.");   
 return 0;
} */
//------------------------------------------------------------------------------
NTSTATUS _stdcall SendIrpSynchronously(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)  // IoForwardIrpSynchronously(pdx->LowerDeviceObject, Irp);
{
 KEVENT   evt;
 NTSTATUS status;
 struct SCALLCACK
  {
   static NTSTATUS DispatchPnpComplete(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp,IN PVOID Context)
    {
     PKEVENT evt = (PKEVENT)Context;
     UNREFERENCED_PARAMETER (DeviceObject);
     if(TRUE == Irp->PendingReturned)KeSetEvent(evt, IO_NO_INCREMENT, FALSE);
     return STATUS_MORE_PROCESSING_REQUIRED;
    }
  };
 //PAGED_CODE();     // Where is KeGetCurrentIrql?
  
 KeInitializeEvent(&evt, NotificationEvent, FALSE);
 IoCopyCurrentIrpStackLocationToNext(Irp);
 IoSetCompletionRoutine(Irp,SCALLCACK::DispatchPnpComplete,&evt,TRUE,TRUE,TRUE);
 status = IoCallDriver(DeviceObject, Irp);
 if(STATUS_PENDING == status)
  {
   KeWaitForSingleObject(&evt,Executive,KernelMode,FALSE,NULL);
   status = Irp->IoStatus.Status;
  } 
 return status;
}
//------------------------------------------------------------------------------
/*UINT _stdcall EnumerateKernelModules(PDRIVER_OBJECT DriverObject)
{
 LDR_MODULE_ENTRY_LO* mlof = (LDR_MODULE_ENTRY_LO*)DriverObject->DriverSection;
 LDR_MODULE_ENTRY_LO* mlon = mlof;    // Last module entry has BaseDllName == NULL; The list is cycled
 UINT mctr = 0;
 do
  {
   if(!mlon)break;                                
   DBGMSG("Module=%wZ", &mlon->Module.BaseDllName);
   mlon = mlon->InLoadOrderLinks.Next;
  }
   while(mlon != mlof);
 return mctr;
} */
//------------------------------------------------------------------------------
PVOID _stdcall KernelGetModuleBase(PDRIVER_OBJECT DriverObject, PCHAR ModuleName) // By internal module name, not by module`s file name
{
 if(!DriverObject || !DriverObject->DriverSection || !ModuleName)return NULL;
 LDR_MODULE_ENTRY_LO* mlof = (LDR_MODULE_ENTRY_LO*)DriverObject->DriverSection;
 while(mlof->Module.BaseModuleName.Buffer && mlof->Module.BaseModuleName.Length)mlof = mlof->InLoadOrderLinks.Next; // Find last (NULL) module entry // On Win7x32 Buffer last pointer is not NULL
 for(;;)
  {
   mlof = mlof->InLoadOrderLinks.Next;
   if(!mlof->Module.BaseModuleName.Buffer)break;  // End of the list
   PWSTR mname = mlof->Module.BaseModuleName.Buffer;
   UINT  mnlen = mlof->Module.BaseModuleName.Length/sizeof(WCHAR);
   UINT  cctr  = 0;
   for(;mnlen && ModuleName[cctr];cctr++,mnlen--)if(!IsCharsEqualIC(mname[cctr],ModuleName[cctr]))break;  // Compare names, LPSTR and UNICODE_STRING
   if(!mnlen && !ModuleName[cctr])return mlof->Module.ModuleBase;
  }
   while(mlof->Module.BaseModuleName.Buffer);
 return NULL;   // Not found
}
//------------------------------------------------------------------------------
UINT _stdcall GetServiceIndexOffset(DWORD SrvIndex, PVOID SrvAddress) // Unsafe but works on all platforms
{
 PBYTE Addr = (PBYTE)SrvAddress; 
 for(UINT ctr=0;ctr < 256;ctr++,Addr++)if(*((PDWORD)Addr) == SrvIndex)return ctr;
 return 0;   // Return wrong offset
}
//------------------------------------------------------------------------------
PVOID _stdcall GetCurrentModule(void)
{
 static ULONG_PTR ModBase = NULL;
 if(!ModBase)ModBase = ~(ULONG_PTR)ModuleAddressToBase(&GetCurrentModule);
 return (PVOID)~ModBase;
}
//------------------------------------------------------------------------------
/*PVOID _stdcall ProcessGetModuleBase(PCHAR ModuleName)  // Untested yet
{
 PVOID    BufPtr = NULL;
 ULONG    MemTag = 'COMN';
 ULONG    BufLen = 256;//0x4000;   // Need test of reallocation!
 NTSTATUS Status = STATUS_SUCCESS;

 DBGMSG("Searching for module: %s",ModuleName);
 do 
  { 
   PVOID BufPtr = ExAllocatePoolWithTag(PagedPool, BufLen, MemTag);
   if(BufPtr == NULL)return NULL;
   Status = ZwQuerySystemInformation(SystemModuleInformation, BufPtr, BufLen, &BufLen);  // Check insufficient buffer
   if(Status == STATUS_INFO_LENGTH_MISMATCH) 
    {
     DBGMSG("Reallocating!");
     ExFreePoolWithTag(BufPtr, MemTag);
     BufLen *= 2;              
    }
  }
   while(STATUS_INFO_LENGTH_MISMATCH == Status);

 if(!NT_SUCCESS(Status))return NULL;
 STRING MName;
 SYSTEM_MODULE_INFORMATION *ModuleInfo  = (SYSTEM_MODULE_INFORMATION*)BufPtr;  
 RtlInitAnsiString(&MName,ModuleName); 
 for(UINT ctr = 0;ctr < ModuleInfo->Count; ctr++)
  {
   STRING CName;
   SYSTEM_MODULE_ENTRY *IModule = &ModuleInfo->Modules[ctr];
   CName.Buffer = &IModule->ModuleFullPath[IModule->PathLength];     // Zero terminated?
   CName.Length = CName.MaximumLength = IModule->NameLength - IModule->PathLength; 
   DBGMSG("Found module: %u, %u, %s",IModule->NameLength,IModule->PathLength,&IModule->ModuleFullPath); 
   if(RtlEqualString(&CName,&MName,TRUE))
    {
     ExFreePoolWithTag(BufPtr, MemTag);
     return ModuleInfo->Modules[ctr].Base;
     break;
    }
  }
 ExFreePoolWithTag(BufPtr, MemTag);
 return NULL;
}*/
//------------------------------------------------------------------------------
void*  __cdecl memset(void* _Dst, int _Val, size_t _Size)
{
//.text:00016BC6                 movzx   eax, byte ptr [ebp+_Val]
//.text:00016BCA                 imul    eax, 1010101h
 for(size_t i = 0;i < _Size;i++)((BYTE*)_Dst)[i] = _Val;
 return _Dst;
}

//------------------------------------------------------------------------------
//    Why optimization is not working in 'DrvFuncs.cpp' and 'DrvMainUnit.cpp'
//------------------------------------------------------------------------------
ULONG_PTR GetKernelBase(PDRIVER_OBJECT DriverObject)
{
 return (ULONG_PTR)KernelGetModuleBase(DriverObject, ENCS("ntoskrnl.exe"));
}
//------------------------------------------------------------------------------
PVOID GetProcNtdllA(PVOID ModBase)
{
 STRING NameProc;
 ENCSN(PtrProc,"ZwProtectVirtualMemory");
 RtlInitAnsiString(&NameProc,PtrProc);
 return GetProcedureAddress(ModBase, &NameProc);  // From ntdll.dll
}
//------------------------------------------------------------------------------
PVOID GetProcNtdllB(PVOID ModBase)
{
 STRING NameProc;
 ENCSN(PtrProc,"ZwClose");
 RtlInitAnsiString(&NameProc,PtrProc);
 return GetProcedureAddress(ModBase, &NameProc);  // From ntdll.dll
}
//------------------------------------------------------------------------------
PVOID GetProcNtoskrnlA(void)
{
 return GetSystemRoutineAddress(ENCS("ZwSetEvent"));  // From ntoskrnl.exe
}
//------------------------------------------------------------------------------
PVOID GetProcNtoskrnlB(void)
{
 return GetSystemRoutineAddress(ENCS("ZwClose"));  // From ntoskrnl.exe
}
//------------------------------------------------------------------------------
void LogResetMessage(UINT FCtr)
{
 DbgPrint(ENCS("%u Failures - SYSTEM RESTART!"),FCtr);  // (__FUNCTION__": %u Failures triggered the system restart!",FCtr)
}
//------------------------------------------------------------------------------
BOOL IsModuleOnPathNtdll(PUNICODE_STRING FullPath)
{
 const int NameLen = sizeof("ntdll.dll");
 UNICODE_STRING NtdllName;
 UNICODE_STRING NtdllCurr;
 ANSI_STRING    TempStr;
 CHAR  TempBuf[NameLen];
 WCHAR NtdllBuf[NameLen];
                          
 if((FullPath->Length/sizeof(WCHAR)) < (NameLen-1))return FALSE;
 TempStr.Buffer   = (CHAR*)&TempBuf;
 TempStr.Length   = TempStr.MaximumLength = NameLen-1;
 NtdllName.Buffer = (PWSTR)&NtdllBuf;
 NtdllName.Length = 0;
 NtdllName.MaximumLength = NameLen * sizeof(WCHAR);
 strcpy((CHAR*)&TempBuf,ENCS("ntdll.dll"));
 RtlAnsiStringToUnicodeString(&NtdllName,&TempStr,FALSE);       
 NtdllCurr.Buffer        = &FullPath->Buffer[(FullPath->Length - NtdllName.Length)/sizeof(WCHAR)];  
 NtdllCurr.MaximumLength = NtdllCurr.Length = NtdllName.Length;
 DBGMSG("Comparing: '%wZ', '%wZ'",&NtdllName,&NtdllCurr);
 return RtlEqualUnicodeString(&NtdllName,&NtdllCurr,TRUE); 
}
//------------------------------------------------------------------------------
BOOL IsModuleOnPath(PUNICODE_STRING ModPath, PUNICODE_STRING FullPath)
{
 UNICODE_STRING ModChkPath;
 UNICODE_STRING ModCurPath;

 // Check Module
 DBGMSG("Checking path: '%wZ'",FullPath);
 ModChkPath.Buffer        = ModPath->Buffer;
 ModChkPath.Length        = ModPath->Length;
 ModChkPath.MaximumLength = ModPath->MaximumLength;

 ModCurPath.Buffer        = FullPath->Buffer;
 ModCurPath.Length        = FullPath->Length;
 ModCurPath.MaximumLength = FullPath->MaximumLength;

 if(ModChkPath.Length > ModCurPath.Length)return 1;    // Specyfy the paths without a drive letter (Windows\explorer.exe)
 UINT dif = (ModCurPath.Length-ModChkPath.Length); 
 ModCurPath.Buffer        += dif/sizeof(WCHAR);
 ModCurPath.Length        -= dif;
 ModCurPath.MaximumLength -= dif; 
 DBGMSG("Comparing: '%wZ', '%wZ'",&ModChkPath,&ModCurPath);  
 return RtlEqualUnicodeString(&ModChkPath,&ModCurPath,TRUE); 
}
//------------------------------------------------------------------------------
BOOL IsUserAddressValid(PVOID Address)
{
 MEMORY_BASIC_INFORMATION mem;
 NTSTATUS resa = ZwQueryVirtualMemory(NtCurrentProcess(),Address,MemoryBasicInformation,&mem,sizeof(mem),NULL);
 DBGMSG("QueryVirtualMemory RESULT = %u",resa);
 if(resa)return FALSE;            
 DBGMSG("Base=%p, Size=%p, Type=%08X, State=%08X, Protect=%08X, ABase=%p, AProtect=%08X",mem.BaseAddress,mem.RegionSize,mem.Type,mem.State,mem.Protect,mem.AllocationBase,mem.AllocationProtect);
 return (mem.State & MEM_COMMIT);
}
//------------------------------------------------------------------------------
//BOOL IsModuleFullyMappedSafe(PVOID Address)  // Use ZwQueryVirtualMemory to test memory ranges
BOOL IsModuleFullyMapped(PVOID Address, SIZE_T Size)
{
 DBGMSG("Base=%p, Size=%p",Address,Size);
 if(Size < sizeof(DOS_HEADER))return FALSE;
 DOS_HEADER* DosHdr  = (DOS_HEADER*)Address;
 if((DosHdr->FlagMZ != SIGN_MZ))return FALSE;
 if(Size < (DosHdr->OffsetHeaderPE+sizeof(WIN_HEADER<PECURRENT>)))return FALSE;
 WIN_HEADER<PECURRENT>* WinHdr = (WIN_HEADER<PECURRENT>*)&(((BYTE*)Address)[DosHdr->OffsetHeaderPE]);
 if((WinHdr->FlagPE != SIGN_PE))return FALSE;
 if(Size < WinHdr->OptionalHeader.SizeOfImage)return FALSE;
 DBGMSG("The modile is OK");
 return TRUE;
}
//------------------------------------------------------------------------------
NTSTATUS GetDeviceNameStr(PUNICODE_STRING Str)
{
 ANSI_STRING TempStr;
 CHAR  StrBuffer[256];

 strcpy((CHAR*)&StrBuffer,ENCS(DEVICEPATH));
 strcat((CHAR*)&StrBuffer,ENCS(DRIVERNAME));
 RtlInitAnsiString(&TempStr,(CHAR*)&StrBuffer);
 return RtlAnsiStringToUnicodeString(Str,&TempStr,FALSE);
}
//------------------------------------------------------------------------------
NTSTATUS GetSymLinkNameStr(PUNICODE_STRING Str)
{
 ANSI_STRING TempStr;
 CHAR  StrBuffer[256];

 strcpy((CHAR*)&StrBuffer,ENCS(SYMLNKPATH));
 strcat((CHAR*)&StrBuffer,ENCS(DRIVERNAME));
 RtlInitAnsiString(&TempStr,(CHAR*)&StrBuffer);
 return RtlAnsiStringToUnicodeString(Str,&TempStr,FALSE);
}
//------------------------------------------------------------------------------
NTSTATUS DeclareCustomDevice(PDRIVER_OBJECT DriverObject, UINT ExtSize, BOOL MakeName, BOOL MakeSymLink)
{
 PDEVICE_OBJECT DeviceObject;  // Can be retrieved later as 'DriverObject->DeviceObject'
 UNICODE_STRING DevName;
 UNICODE_STRING SymLName;
 WCHAR UStrBuffer1[128];
 WCHAR UStrBuffer2[128];

 if(MakeName)
  {
   DevName.Buffer = (WCHAR*)&UStrBuffer1;
   DevName.Length = DevName.MaximumLength = sizeof(UStrBuffer1);
   GetDeviceNameStr(&DevName);
  }
 NTSTATUS Status = IoCreateDevice(DriverObject,ExtSize,(MakeName)?(&DevName):(NULL),FILE_DEVICE_CUSTOM,FILE_DEVICE_SECURE_OPEN,EXCLUSIVEOPEN,&DeviceObject);      // FILE_CHARACTERISTIC_PNP_DEVICE   
 DBGMSG("Device created, result=%u.",Status);
 if(!NT_SUCCESS(Status))return Status; 

 if(MakeSymLink)
  {
   SymLName.Buffer = (WCHAR*)&UStrBuffer2;
   SymLName.Length = SymLName.MaximumLength = sizeof(UStrBuffer2);
   GetSymLinkNameStr(&SymLName);

   Status = IoCreateSymbolicLink(&SymLName, &DevName);
   DBGMSG("SymLink created, result=%u.",Status);
  }
 return Status;
}
//------------------------------------------------------------------------------
NTSTATUS DestroyCustomDevice(PDEVICE_OBJECT DeviceObject)
{
 UNICODE_STRING SymLName;
 WCHAR UStrBuffer[128];

 SymLName.Buffer = (WCHAR*)&UStrBuffer;
 SymLName.Length = SymLName.MaximumLength = sizeof(UStrBuffer);
 GetSymLinkNameStr(&SymLName);
 NTSTATUS Status = IoDeleteSymbolicLink(&SymLName);
 DBGMSG("SymLink removed, result=%08X.",Status);  
 IoDeleteDevice(DeviceObject);  // Deallocates memory of DevExt 
 return STATUS_SUCCESS;
}
//------------------------------------------------------------------------------
