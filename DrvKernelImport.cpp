
#include "DrvKernelImport.h"


extern ULONG_PTR KernelBase;
//===========================================================================
//
//---------------------------------------------------------------------------
ULONG_PTR _stdcall GetImportedProc(LPSTR ProcName,LPSTR ModuleName=NULL)
{
 PVOID Addr = OIGetProcAddress((PVOID)~KernelBase, ProcName);
 if(!Addr)Addr = GetSystemRoutineAddress(ProcName);
 return (ULONG_PTR)Addr;
}
//===========================================================================
VOID HalReturnToFirmware(FIRMWARE_REENTRY Routine)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(FIRMWARE_REENTRY))~Proc)(Routine);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION Action)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(SHUTDOWN_ACTION))~Proc)(Action);
}
//---------------------------------------------------------------------------
VOID KeBugCheckEx(ULONG BugCheckCode, ULONG_PTR BugCheckParameter1, ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter3, ULONG_PTR BugCheckParameter4)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(ULONG,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))~Proc)(BugCheckCode,BugCheckParameter1,BugCheckParameter2,BugCheckParameter3,BugCheckParameter4);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG))~Proc)(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);
}
//---------------------------------------------------------------------------
NTSTATUS IoCreateDevice(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (*)(PDRIVER_OBJECT,ULONG,PUNICODE_STRING,DEVICE_TYPE,ULONG,BOOLEAN,PDEVICE_OBJECT*))~Proc)(DriverObject,DeviceExtensionSize,DeviceName,DeviceType,DeviceCharacteristics,Exclusive,DeviceObject);
}
//---------------------------------------------------------------------------
VOID KeInitializeEvent(PRKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PRKEVENT,EVENT_TYPE,BOOLEAN))~Proc)(Event,Type,State);
}
//---------------------------------------------------------------------------
VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (NTAPI*)(PUNICODE_STRING,PCWSTR))~Proc)(DestinationString,SourceString);
}
//---------------------------------------------------------------------------
PDEVICE_OBJECT IoAttachDeviceToDeviceStack(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((PDEVICE_OBJECT (*)(PDEVICE_OBJECT,PDEVICE_OBJECT))~Proc)(SourceDevice,TargetDevice);
}
//---------------------------------------------------------------------------
VOID FASTCALL IofCompleteRequest(PIRP Irp, CCHAR PriorityBoost)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (FASTCALL*)(PIRP,CCHAR))~Proc)(Irp,PriorityBoost);
}
//---------------------------------------------------------------------------
BOOLEAN KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((BOOLEAN (*)(PKTIMER,LARGE_INTEGER,PKDPC))~Proc)(Timer,DueTime,Dpc);
}
//---------------------------------------------------------------------------
NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (*)(PVOID,KWAIT_REASON,KPROCESSOR_MODE,BOOLEAN,PLARGE_INTEGER))~Proc)(Object,WaitReason,WaitMode,Alertable,Timeout);
}
//---------------------------------------------------------------------------
PVOID NTAPI ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((PVOID (NTAPI*)(POOL_TYPE,SIZE_T,ULONG))~Proc)(PoolType,NumberOfBytes,Tag);
}
//---------------------------------------------------------------------------
VOID ExFreePoolWithTag(PVOID P, ULONG Tag)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PVOID,ULONG))~Proc)(P,Tag);
}
//---------------------------------------------------------------------------
VOID FASTCALL ExReleaseFastMutex(PFAST_MUTEX FastMutex)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (FASTCALL*)(PFAST_MUTEX))~Proc)(FastMutex);
}
//---------------------------------------------------------------------------
VOID FASTCALL ExAcquireFastMutex(PFAST_MUTEX FastMutex)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (FASTCALL*)(PFAST_MUTEX))~Proc)(FastMutex);
}
//---------------------------------------------------------------------------
NTSTATUS FASTCALL IofCallDriver(PDEVICE_OBJECT DeviceObject,  PIRP Irp)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (FASTCALL*)(PDEVICE_OBJECT,PIRP))~Proc)(DeviceObject,Irp);
}
//---------------------------------------------------------------------------
LONG KeSetEvent(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((LONG (*)(PRKEVENT,KPRIORITY,BOOLEAN))~Proc)(Event,Increment,Wait);
}
//---------------------------------------------------------------------------
VOID NTAPI RtlAssert(PVOID FailedAssertion, PVOID FileName, ULONG LineNumber, PCHAR Message)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (NTAPI*)(PVOID,PVOID,ULONG,PCHAR))~Proc)(FailedAssertion,FileName,LineNumber,Message);
}
//---------------------------------------------------------------------------
BOOLEAN KeCancelTimer(PKTIMER Timer)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((BOOLEAN (*)(PKTIMER))~Proc)(Timer);
}
//---------------------------------------------------------------------------
VOID KeFlushQueuedDpcs(VOID)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(void))~Proc)();
}
//---------------------------------------------------------------------------
VOID IoFreeWorkItem(PIO_WORKITEM IoWorkItem)
{
 static ULONG_PTR Proc = 0;     
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PIO_WORKITEM))~Proc)(IoWorkItem);
}
//---------------------------------------------------------------------------
NTSTATUS PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (*)(PLOAD_IMAGE_NOTIFY_ROUTINE))~Proc)(NotifyRoutine);
}
//---------------------------------------------------------------------------
NTSTATUS PsRemoveLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (*)(PLOAD_IMAGE_NOTIFY_ROUTINE))~Proc)(NotifyRoutine);
}
//---------------------------------------------------------------------------
VOID IoDetachDevice( PDEVICE_OBJECT TargetDevice)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PDEVICE_OBJECT))~Proc)(TargetDevice);
}
//---------------------------------------------------------------------------
VOID IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PDEVICE_OBJECT))~Proc)(DeviceObject);
}
//---------------------------------------------------------------------------
NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (*)(PUNICODE_STRING,PUNICODE_STRING))~Proc)(SymbolicLinkName,DeviceName);
}
//---------------------------------------------------------------------------
NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (*)(PUNICODE_STRING))~Proc)(SymbolicLinkName);
}
//---------------------------------------------------------------------------
PIO_WORKITEM IoAllocateWorkItem(PDEVICE_OBJECT DeviceObject)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((PIO_WORKITEM (*)(PDEVICE_OBJECT))~Proc)(DeviceObject);
}
//---------------------------------------------------------------------------
VOID KeInitializeTimerEx(PKTIMER Timer, TIMER_TYPE Type)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PKTIMER,TIMER_TYPE))~Proc)(Timer,Type);
}
//---------------------------------------------------------------------------
VOID KeInitializeDpc(PRKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PRKDPC,PKDEFERRED_ROUTINE,PVOID))~Proc)(Dpc,DeferredRoutine,DeferredContext);
}
//---------------------------------------------------------------------------
VOID IoQueueWorkItem(PIO_WORKITEM IoWorkItem, PIO_WORKITEM_ROUTINE WorkerRoutine, WORK_QUEUE_TYPE QueueType, PVOID Context)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PIO_WORKITEM,PIO_WORKITEM_ROUTINE,WORK_QUEUE_TYPE,PVOID))~Proc)(IoWorkItem,WorkerRoutine,QueueType,Context);
}
//---------------------------------------------------------------------------
BOOLEAN NTAPI RtlEqualUnicodeString(const UNICODE_STRING *String1, const UNICODE_STRING *String2, BOOLEAN CaseInSensitive)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((BOOLEAN (NTAPI*)(const UNICODE_STRING*,const UNICODE_STRING*,BOOLEAN))~Proc)(String1,String2,CaseInSensitive);
}
//---------------------------------------------------------------------------
VOID NTAPI RtlInitAnsiString(PANSI_STRING DestinationString, PCSZ SourceString)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (NTAPI*)(PANSI_STRING,PCSZ))~Proc)(DestinationString,SourceString);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(PUNICODE_STRING,PCANSI_STRING,BOOLEAN))~Proc)(DestinationString,SourceString,AllocateDestinationString);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI RtlUnicodeStringToAnsiString(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(PANSI_STRING,PCUNICODE_STRING,BOOLEAN))~Proc)(DestinationString,SourceString,AllocateDestinationString);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI RtlCheckRegistryKey(ULONG RelativeTo, PWSTR Path)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(ULONG,PWSTR))~Proc)(RelativeTo,Path);
}
//---------------------------------------------------------------------------
BOOLEAN NTAPI RtlEqualString(const STRING * String1, const STRING * String2, BOOLEAN CaseInSensitive)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((BOOLEAN (NTAPI*)(const STRING*,const STRING*,BOOLEAN))~Proc)(String1,String2,CaseInSensitive);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI RtlQueryRegistryValues(ULONG RelativeTo, PCWSTR Path, PRTL_QUERY_REGISTRY_TABLE QueryTable, PVOID Context, PVOID Environment)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(ULONG,PCWSTR,PRTL_QUERY_REGISTRY_TABLE,PVOID,PVOID))~Proc)(RelativeTo,Path,QueryTable,Context,Environment);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI ZwClose(HANDLE Handle)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(HANDLE))~Proc)(Handle);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG))~Proc)(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,ShareAccess,OpenOptions);
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI ZwReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG))~Proc)(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,Buffer,Length,ByteOffset,Key);
}
//---------------------------------------------------------------------------
PVOID MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
 static ULONG_PTR Proc = 0;    
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((PVOID (*)(PUNICODE_STRING))~Proc)(SystemRoutineName);
}
//---------------------------------------------------------------------------
BOOLEAN MmIsAddressValid(PVOID VirtualAddress)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((BOOLEAN (*)(PVOID))~Proc)(VirtualAddress);
}
//---------------------------------------------------------------------------
VOID KeInitializeApc(PKAPC Apc, PKTHREAD Thread, UCHAR StateIndex, PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine, PKNORMAL_ROUTINE NormalRoutine, KPROCESSOR_MODE ApcMode, PVOID NormalContext)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PKAPC,PKTHREAD,UCHAR,PKKERNEL_ROUTINE,PKRUNDOWN_ROUTINE,PKNORMAL_ROUTINE,KPROCESSOR_MODE,PVOID))~Proc)(Apc,Thread,StateIndex,KernelRoutine,RundownRoutine,NormalRoutine,ApcMode,NormalContext);
}
//---------------------------------------------------------------------------
BOOLEAN KeInsertQueueApc(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((BOOLEAN (*)(PKAPC,PVOID,PVOID,KPRIORITY))~Proc)(Apc,SystemArgument1,SystemArgument2,Increment);
}
//---------------------------------------------------------------------------
PRKTHREAD KeGetCurrentThread(void)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((PRKTHREAD (*)(void))~Proc)();
}
//---------------------------------------------------------------------------
HANDLE PsGetCurrentThreadId(void)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((HANDLE (*)(void))~Proc)();
}
//---------------------------------------------------------------------------
KPROCESSOR_MODE ExGetPreviousMode(VOID)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((KPROCESSOR_MODE (*)(void))~Proc)();
}
//---------------------------------------------------------------------------
NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, ULONG Length, PULONG ResultLength)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((NTSTATUS (NTAPI*)(HANDLE,PVOID,MEMORY_INFORMATION_CLASS,PVOID,ULONG,PULONG))~Proc)(ProcessHandle,BaseAddress,MemoryInformationClass,Buffer,Length,ResultLength);
}
//---------------------------------------------------------------------------
#ifndef KeQuerySystemTime
VOID KeQuerySystemTime(PLARGE_INTEGER CurrentTime)       // x32 only
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (*)(PLARGE_INTEGER))~Proc)(CurrentTime);
}
#endif
//---------------------------------------------------------------------------
#ifndef _AMD64_
VOID NTAPI WRITE_PORT_UCHAR(PUCHAR Port, UCHAR  Value)   // x32 only
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (NTAPI*)(PUCHAR,UCHAR))~Proc)(Port,Value);
}
#endif
//---------------------------------------------------------------------------
SIZE_T NTAPI RtlCompareMemory(const VOID *Source1, const VOID *Source2, SIZE_T Length)
{
 static ULONG_PTR Proc = 0;    
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((SIZE_T (NTAPI*)(const VOID*,const VOID*,SIZE_T))~Proc)(Source1,Source2,Length);
}
//---------------------------------------------------------------------------
#ifndef RtlCopyMemory
VOID NTAPI RtlCopyMemory(VOID UNALIGNED *Destination, CONST VOID UNALIGNED *Source, SIZE_T Length)
{     
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 ((VOID (NTAPI*)(VOID*,CONST VOID*,SIZE_T))~Proc)(Destination,Source,Length);
}
#else      // x32
void* __cdecl memcpy(void* _Dst, const void* _Src, size_t _Size)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((void* (__cdecl*)(void*,const void*,size_t))~Proc)(_Dst,_Src,_Size);
}
#endif
//---------------------------------------------------------------------------
int __cdecl wcsncmp(const wchar_t * _Str1, const wchar_t * _Str2, size_t _MaxCount)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((int (__cdecl*)(const wchar_t*,const wchar_t*,size_t))~Proc)(_Str1,_Str2,_MaxCount);
}          
//---------------------------------------------------------------------------
/*size_t __cdecl wcslen(const wchar_t * _Str)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((size_t (__cdecl*)(const wchar_t*))~Proc)(_Str);
}*/
//---------------------------------------------------------------------------
/*size_t __cdecl strlen(const char * _Str)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((size_t (__cdecl*)(const char*))~Proc)(_Str);
}*/
//---------------------------------------------------------------------------
extern "C" unsigned __int64 _cdecl _allmul(unsigned __int64 multiplicand, unsigned __int64 multiplier)
{
 static ULONG_PTR Proc = 0;
 if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
 return ((unsigned __int64 (_stdcall*)(unsigned __int64,unsigned __int64))~Proc)(multiplicand,multiplier);
}
//---------------------------------------------------------------------------
//void* _C_specific_handler;

//{
// static ULONG_PTR Proc = 0;
// if(!Proc)Proc = ~GetImportedProc(ENCS(__FUNCTION__));
// return ExceptionContinueExecution;//((EXCEPTION_DISPOSITION (__cdecl*)(struct _EXCEPTION_RECORD*,unsigned __int64,unsigned __int64,struct _CONTEXT*,struct _DISPATCHER_CONTEXT*,unsigned __int64))~Proc)(_ExceptionRecord,_MemoryStackFp,_BackingStoreFp,_ContextRecord,_DispatcherContext,_GlobalPointer);
//}
//---------------------------------------------------------------------------
/*#ifdef _AMD64_
EXCEPTION_DISPOSITION _cdecl C_specific_handler(struct _EXCEPTION_RECORD *_ExceptionRecord, unsigned __int64 _MemoryStackFp, unsigned __int64 _BackingStoreFp, struct _CONTEXT *_ContextRecord, struct _DISPATCHER_CONTEXT *_DispatcherContext, unsigned __int64 _GlobalPointer)
{
 DBGMSG("An Exception occured!");   
 return ExceptionContinueExecution;
}
extern "C" void _cdecl __C_specific_handler(void)
{
 ((void (_cdecl *)(void))C_specific_handler)();  // Optimized as a single JMP
}
#else      // x32

#endif */
//---------------------------------------------------------------------------
ULONG __cdecl DbgPrint(PCH Format, ...)
{
 static ULONG_PTR Proc = 0;
 if(Proc < 2)
  {
   if(Proc)return 0;   // No self locking!
   Proc = 1;
   Proc = ~GetImportedProc(ENCS("vDbgPrintEx")); 
  }   
 return ((ULONG (*)(ULONG,ULONG,PCH,ULONG_PTR*))~Proc)(0,0,Format,&((ULONG_PTR*)&Format)[1]);
}
//---------------------------------------------------------------------------
