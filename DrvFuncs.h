#pragma once


#include "DrvKernelImport.h"
#include "DrvParams.h"
#include "DrvUtils.h"
#include "DrvMD5.h"
//------------------------------------------------------------------------------
#define LDRTESTONLYEXE   // Exhange API in EXE files only


#define CO_SKIP 0     // No action
#define CO_FILE 1     // FILE,   MD5
#define CO_FLDR 2     // FOLDER, NONE
#define CO_RVAL 4     // RECORD, VALUE    
#define CO_RKEY 5     // KEY,    NONE
#define CO_PROC 6     // Replaced imported API  // Do not cpecify disk in path
      
//-----------------------------------------------------------------
NTSTATUS ProcessDeviceInitialization(PDEVICE_OBJECT DeviceObject);
UINT     WorkCheckFile(PUNICODE_STRING FilePath, PUNICODE_STRING FileMD5);
UINT     WorkCheckFolder(PUNICODE_STRING FolderPath);
UINT     WorkCheckRegVal(PUNICODE_STRING ValPath, PUNICODE_STRING ValName, PUNICODE_STRING Value);
UINT     WorkCheckRegKey(PUNICODE_STRING KeyPath);
UINT     WorkCheckNewModule(PUNICODE_STRING ModPath, PUNICODE_STRING FullPath, PVOID Address, UINT Size);
UINT     FindProcProtVirtMem(PUNICODE_STRING FullPath, PVOID Address, UINT Size);

VOID WrkTimerDpc(IN struct _KDPC *Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2);
VOID TmrWorkItemProc(IN PDEVICE_OBJECT  DeviceObject, IN PVOID  Context);
VOID NotifyLoadImageProc(IN PUNICODE_STRING FullImageName,IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
template<typename T> UINT ExchangeImportEntriesByName(PSTRING ModuleName, PSTRING ProcNameA, PSTRING ProcNameB, PVOID ModuleBase);
template<typename T> UINT ExchangeImportEntries(T* EnttryA, T* EnttryB);
//------------------------------------------------------------------------------
struct DEVICE_EXTENSION
{
 PDRIVER_OBJECT doDriver;
 PDEVICE_OBJECT deNextDev;
 PDEVICE_OBJECT dePhysDev;

 LARGE_INTEGER Interval;
 FAST_MUTEX    MFMutex;
 PIRP   LastIrp;
 PVOID  InputBuffer;
 PVOID  ResultBuffer;
 UINT   InputBufLen;
 UINT   ResultBufLen;

 PIO_WORKITEM pTmrWItem;
 KTIMER       WrkTimer;
 KDPC         TmrDpc;

 BOOL Terminating;

 void FreeResources(void)
  {   
   if(this->Terminating)return;
   this->Terminating = TRUE;
   DBGMSG("Entering..."); 
   KeCancelTimer(&this->WrkTimer);
   KeFlushQueuedDpcs();     
   DBGMSG("Removing 'LoadImageNotifyRoutine'...");
   PsRemoveLoadImageNotifyRoutine(NotifyLoadImageProc);
   DBGMSG("Removing other objects...");

   //ExAcquireFastMutex(&this->MFMutex);         // Incompatible with ZwReadFile // WorkItem callback must be complete // Watch out for a callers of FreeResources with already acquired mutex!
   if(this->pTmrWItem){IoFreeWorkItem(this->pTmrWItem);this->pTmrWItem=NULL;}  // Only free a work item that is not currently queued. // TODO: Test if queued
   //ExReleaseFastMutex(&this->MFMutex);
   if(this->deNextDev){IoDetachDevice(this->deNextDev);this->deNextDev=NULL;} 
   if(this->doDriver->DeviceObject)DestroyCustomDevice(this->doDriver->DeviceObject); 

   DBGMSG("Finished."); 
  }
};
typedef DEVICE_EXTENSION* PDEVICE_EXTENSION;
//------------------------------------------------------------------------------
#pragma optimize( "", off )
static void MemFillZero(PVOID pData, UINT nLength)
{
 UINT i=nLength/4;
 for(;i > 0;i--){((ULONG*)pData)[0]=0;pData = ((ULONG*)pData)+1;}
 i = nLength%4;
 for(;i > 0;i--){((BYTE*)pData)[0]=0;pData = ((BYTE*)pData)+1;}
}
//------------------------------------------------------------------------------
struct SExApiAPC
{
 KAPC   apc;
 BYTE   Padding[256];
 PVOID  ModuleBase;
 ULONG  ModuleSize;
 HANDLE ThreadId;
 UNICODE_STRING FullImageName;
 WCHAR  ModulePathBuf[256];
};

VOID KernelApcCallback(IN struct _KAPC *Apc,IN OUT PKNORMAL_ROUTINE *NormalRoutine,IN OUT PVOID *NormalContext,IN OUT PVOID *SystemArgument1,IN OUT PVOID *SystemArgument2);
//------------------------------------------------------------------------------