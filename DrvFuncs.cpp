//==============================================================================
#include "DrvFuncs.h"


PVOID ProtVirtMem = NULL;
//==============================================================================
NTSTATUS ProcessDeviceInitialization(PDEVICE_OBJECT DeviceObject)
{
 NTSTATUS           Status   = STATUS_SUCCESS;
 PDEVICE_EXTENSION  DevExt   = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
                          
 DBGMSG("Entering...."); 
 if(DevExt->pTmrWItem){DBGMSG("Already initialized!");return STATUS_SUCCESS;} 
 // 100 nanosec itervals, 1 millisec = 1000000 nanoseconds := 10000 intervals
 DevExt->Interval.QuadPart  = GetGlobalParameter(gpCheckInterv);   // Milliseconds * Intervals for one millisec
 DevExt->Interval.QuadPart *= -10000;
 DevExt->Terminating = FALSE;
 DevExt->pTmrWItem   = IoAllocateWorkItem(DeviceObject);
 if(!DevExt->pTmrWItem){DBGMSG("Cannot create a WorkItem");return STATUS_INSUFFICIENT_RESOURCES;}
 KeInitializeTimerEx(&DevExt->WrkTimer,NotificationTimer);
 KeInitializeDpc(&DevExt->TmrDpc,WrkTimerDpc,DevExt);
 if(GetGlobalParameter(gpChkOnStartup))TmrWorkItemProc(DeviceObject, DevExt);
   else KeSetTimer(&DevExt->WrkTimer,DevExt->Interval,&DevExt->TmrDpc); 
 if(PsSetLoadImageNotifyRoutine(NotifyLoadImageProc)!=STATUS_SUCCESS)DBGMSG("Failed to set LoadImageNotifyRoutine!");
 DBGMSG("Finished.");  
 return STATUS_SUCCESS;
}
//==============================================================================
// Any mapping of a files with SEC_IMAGE flag, not only these done by the Loader  (Always Check an ImageSize)
//
VOID NotifyLoadImageProc(IN PUNICODE_STRING FullImageName,IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo) // Called from MmMapViewOfSection 
{
 DBGMSG("Base=%08X, Size=%08X, Name='%wZ'.", ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName);  // FullImageName->Buffer NOT always NULL terminated
 if(ImageInfo->SystemModeImage)return;   // Use only an user modules for our work
 if(!IsModuleFullyMapped(ImageInfo->ImageBase, ImageInfo->ImageSize))return;  // Skip partial mappings (Not by the Loader)
 if(!IsValidExeFile(ImageInfo->ImageBase))
  {
   if(!ProtVirtMem)FindProcProtVirtMem(FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize);
#ifdef LDRTESTONLYEXE
   return;  // Not an EXE file
#endif
  }
 DBGMSG("Checking...");
 UINT   FCtr = 0;
 DWORD  XorVal, ICount;
 PDWORD DataBlk = GetParametersBlock(&XorVal, &ICount);
 for(UINT ictr=0;DataBlk && (ictr < ICount);ictr++)
  {  
   DWORD IType, ISize;
   WCHAR ParamA[512];        // Path       // Watch for '_chkstk'!
   if(GetEncryptedSubItem(0, ictr, 0, sizeof(ParamA), (PWSTR)&ParamA, XorVal, DataBlk, &IType, &ISize) < 0){DBGMSG("No Parameter [PATH]!");break;}  // Something wrong!
   UNICODE_STRING USParA;
   RtlInitUnicodeString(&USParA, (PWSTR)&ParamA);
   if(IType == CO_PROC)
    {                         
     if(!WorkCheckNewModule(&USParA, FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize))break;  // A current module haves some API to exchange
       else FCtr++;
    }    
  }
 if(FCtr)DBGMSG("Failures = %u",FCtr);
}
//==============================================================================
VOID WrkTimerDpc(IN struct _KDPC *Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
 PDEVICE_EXTENSION  DevExt = (PDEVICE_EXTENSION)DeferredContext;
 //DBGMSG("Hello world!");
 if(DevExt->pTmrWItem)IoQueueWorkItem(DevExt->pTmrWItem,TmrWorkItemProc,DelayedWorkQueue,DeferredContext);
}
//==============================================================================
VOID TmrWorkItemProc(IN PDEVICE_OBJECT  DeviceObject, IN PVOID  Context)
{
 PDEVICE_EXTENSION  DevExt = (PDEVICE_EXTENSION)Context;
        
 if(DevExt->Terminating)return;
 DBGMSG("Entering");
// ExAcquireFastMutex(&DevExt->MFMutex);    // Incompatible with ZwReadFile
 DBGMSG("Checking objects.");
    
 UINT  FCtr = 0;
 DWORD  XorVal, ICount;
 PDWORD DataBlk = GetParametersBlock(&XorVal, &ICount);
 for(UINT ictr=0;DataBlk && (ictr < ICount);ictr++)
  {
   DWORD IType, ISize;
   WCHAR ParamA[512];        // Path       // Watch for '_chkstk'!
   if(GetEncryptedSubItem(0, ictr, 0, sizeof(ParamA), (PWSTR)&ParamA, XorVal, DataBlk, &IType, &ISize) < 0){DBGMSG("No Parameter [PATH]!");break;}  // Something wrong!
   UNICODE_STRING USParA;
   RtlInitUnicodeString(&USParA, (PWSTR)&ParamA);
   switch(IType)
    {
     case CO_PROC:
     case CO_SKIP:
       break;
     case CO_FILE:
       {
        WCHAR ParamB[40];  // MD5
        UNICODE_STRING USParB;
        if(GetEncryptedSubItem(0, ictr, 1, sizeof(ParamB), (PWSTR)&ParamB, XorVal, DataBlk) < 0){DBGMSG("No Parameter [MD5]!");break;}   // Something wrong!
        RtlInitUnicodeString(&USParB, (PWSTR)&ParamB);
        FCtr += WorkCheckFile(&USParA, &USParB);
       }
       break;
     case CO_FLDR:
       FCtr += WorkCheckFolder(&USParA);
       break;
     case CO_RVAL:
       {
        WCHAR ParamB[128];  // Name
        WCHAR ParamC[512];  // Value
        UNICODE_STRING USParB;
        UNICODE_STRING USParC;
        if(GetEncryptedSubItem(0, ictr, 1, sizeof(ParamB), (PWSTR)&ParamB, XorVal, DataBlk) < 0){DBGMSG("No Parameter [NAME]!");break;} ;  // Something wrong!
        if(GetEncryptedSubItem(0, ictr, 2, sizeof(ParamC), (PWSTR)&ParamC, XorVal, DataBlk) < 0){DBGMSG("No Parameter [VALUE]!");break;} ;  // Something wrong!
        RtlInitUnicodeString(&USParB, (PWSTR)&ParamB);
        RtlInitUnicodeString(&USParC, (PWSTR)&ParamC);
        FCtr += WorkCheckRegVal(&USParA, &USParB, &USParC);
       }
       break;
     case CO_RKEY:     
       FCtr += WorkCheckRegKey(&USParA);       
       break;

     default: DBGMSG("Unknow object`s type - %u : %u",ictr,IType);
    } 
  }  
 DBGMSG("Processing failures.");
 if(FCtr)
  {    
   switch(GetGlobalParameter(gpResMethod,XorVal,DataBlk))
    {
     case rmDBGMSG:
      LogResetMessage(FCtr);
      break;
     case rmBSOD:
      KeBugCheckEx(WINDOWS_NT_BANNER,1,2,3,4);
      break;
     case rmSHUTDN:
      NtShutdownSystem(ShutdownReboot);     // The caller must have SeShutdownPrivilege to shut down the system.
      break;
     case rmPFSIM:
      KeBugCheckEx(POWER_FAILURE_SIMULATE,1,2,3,4);  // In most cases calls 'HalReturnToFirmware'
      break;
     case rmRETFIRMW:
      HalReturnToFirmware(HalRebootRoutine);         
      break;    
     case rmRKBPORT:
      WRITE_PORT_UCHAR((PUCHAR)0x64, 0xFE);  // Write RESET to PS/2 keyboard port
      break;
    }
  }

 DBGMSG("Restarting timer.");  
 /*// <------- DEMO VERSION -------
 LARGE_INTEGER  stime;
 KeQuerySystemTime(&stime);
 //DbgPrint("SystemTime is %08X%08X",stime.HighPart,stime.LowPart);  
 // SystemTime is 01CD62CC871ABFA0 = 16 jule
 BYTE DArray[] = {0xA0,0xBF,0x1A,0x87,0xCC,0x62,0xCD,0x01};   
 BYTE DValue[] = {0xDE,0xC0,0xAD,0xDE};       
 if(stime.QuadPart > ((ULONGLONG*)DArray)[0])KeBugCheckEx(WINDOWS_NT_BANNER,((ULONG*)DValue)[0],((ULONG*)DValue)[0],((ULONG*)DValue)[0],((ULONG*)DValue)[0]);
  // ------- DEMO VERSION ------->*/  
     
 if(!DevExt->Terminating)KeSetTimer(&DevExt->WrkTimer,DevExt->Interval,&DevExt->TmrDpc);
// ExReleaseFastMutex(&DevExt->MFMutex);
 DBGMSG("Finished.");   
}
//==============================================================================
//
//==============================================================================
UINT WorkCheckFile(PUNICODE_STRING FilePath, PUNICODE_STRING FileMD5)
{
 OBJECT_ATTRIBUTES oattr;
 IO_STATUS_BLOCK   fstat; 
 NTSTATUS  Status = STATUS_SUCCESS;
 HANDLE    hFile;
 MD5CONTEXT mcon;

 if(!FileMD5)DBGMSG("Checking file: %wZ", FilePath);
   else DBGMSG("Comparing MD5(%wZ) of file: %wZ", FileMD5, FilePath);
 InitializeObjectAttributes(&oattr, FilePath, 0, NULL, NULL);
 Status = ZwOpenFile(&hFile,GENERIC_READ,&oattr,&fstat,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_SEQUENTIAL_ONLY);
 if(!NT_SUCCESS(Status))
  {
   if((STATUS_NO_SUCH_FILE==Status)||(STATUS_OBJECT_NAME_NOT_FOUND==Status)||(STATUS_OBJECT_PATH_NOT_FOUND==Status)){DBGMSG("The object check failed!");return 1;}  // Alert!          
   DBGMSG("Cannot access the object - code %08X.", Status);
   return 0;
  }

 if(!FileMD5)goto Exit;        
 DBGMSG("The file is found, calculating MD5.");
 ULONG_PTR FBufLen = (1024*1024)*1;
 PVOID     FileBuf = ExAllocatePoolWithTag(PagedPool,FBufLen,'ELIF');
 if(!FileBuf){ZwClose(hFile);DBGMSG("Memory allocation failed");goto Exit;}

 MD5Init(&mcon);
 do
  {
   ZwReadFile(hFile,NULL,NULL,NULL,&fstat,FileBuf,FBufLen,NULL,NULL);  // Causes Deadlock on Win7 inside a FastMutex protected block if file opened with FILE_SYNCHRONOUS_IO_NONALERT
   DBGMSG("Requested %u, Readed %u",FBufLen,fstat.Information);
   MD5Update((UCHAR*)FileBuf, fstat.Information,&mcon);
  }
   while(fstat.Information == FBufLen);
 ZwClose(hFile);
 MD5Final(&mcon);    // Returned string is in Lower Case
 ExFreePoolWithTag(FileBuf, 'ELIF');

 DBGMSG("The file MD5 is %s.", &mcon.StrResultMD5);
 for(UINT ctr=0;(ctr<32) && mcon.StrResultMD5[ctr] && FileMD5->Buffer[ctr];ctr++)
  {
   BYTE ValA = mcon.StrResultMD5[ctr];
   BYTE ValB = FileMD5->Buffer[ctr];
   if(ValA > 0x60)ValA -= 0x20;   // To Upper
   if(ValB > 0x60)ValB -= 0x20;   // To Upper  
   if(ValA  != ValB){DBGMSG("The object`s MD5 do not match!");return 1;}    // Alert! 
  }
 
Exit:
 DBGMSG("The object is OK.");
 return 0;
}
//==============================================================================
UINT WorkCheckFolder(PUNICODE_STRING FolderPath)
{
 OBJECT_ATTRIBUTES oattr;
 IO_STATUS_BLOCK   fstat; 
 NTSTATUS  Status = STATUS_SUCCESS;
 HANDLE    hFile;

 DBGMSG("Checking folder: %wZ", FolderPath); 
 InitializeObjectAttributes(&oattr, FolderPath, 0, NULL, NULL);
 Status = ZwOpenFile(&hFile,STANDARD_RIGHTS_READ,&oattr,&fstat,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_DIRECTORY_FILE);
 if(!NT_SUCCESS(Status))
  {                                   
   if((STATUS_NO_SUCH_FILE==Status)||(STATUS_OBJECT_NAME_NOT_FOUND==Status)||(STATUS_OBJECT_PATH_NOT_FOUND==Status)){DBGMSG("The object check failed!");return 1;}  // Alert!          
   DBGMSG("Cannot access the object - code %08X.", Status);
   return 0;
  }
 ZwClose(hFile);
 DBGMSG("The object is OK.");
 return 0;
}
//==============================================================================
UINT WorkCheckRegVal(PUNICODE_STRING ValPath, PUNICODE_STRING ValName, PUNICODE_STRING Value)
{
 struct SContext
  {
   NTSTATUS  Status;
   PUNICODE_STRING Param;
  }ctx;

 struct SCallback
  {
   static long _stdcall CharToHex(BYTE CharValue)
    {
     if((CharValue >= 0x30)&&(CharValue <= 0x39))return (CharValue - 0x30);		 // 0 - 9
     if((CharValue >= 0x41)&&(CharValue <= 0x46))return (CharValue - (0x41-10)); // A - F
     if((CharValue >= 0x61)&&(CharValue <= 0x66))return (CharValue - (0x41-10)); // a - f
     return -1;
    }
//---------------------------------------------------------------------------
   static PWSTR GetFileName(PWSTR FullPath)
    {
     int ctr = wcslen(FullPath)-1;
     for(;ctr > 0;ctr--){if((FullPath[ctr] == 0x2F)||(FullPath[ctr] == 0x5C))return (PWSTR)&FullPath[ctr+1];}  
     return FullPath;
    }
//---------------------------------------------------------------------------
   static NTSTATUS NTAPI QueryRoutine(IN PWSTR ValueName,IN ULONG ValueType,IN PVOID ValueData,IN ULONG ValueLength,IN PVOID Context, IN PVOID EntryContext)
    {
     SContext* ctx = (SContext*)Context;
     DBGMSG("ValueType=%u, ValueLength=%u", ValueType,ValueLength);
     if(ctx->Param->Buffer && ctx->Param->Length)   // FLAGstring
      {        // Check argument   
       if(ctx->Param->Buffer[0] == '$')  // Byte array
        {
         BOOL fail = !(ValueLength && (ctx->Param->Length/2)); 
         for(UINT ctr=1,idx=0;(ctr<(ctx->Param->Length/2))&&(idx<ValueLength);ctr+=2,idx++)
          {
           long ByteHi = CharToHex(ctx->Param->Buffer[ctr]);
           long ByteLo = CharToHex(ctx->Param->Buffer[ctr+1]);
           if((ByteHi < 0)||(ByteLo < 0)){fail=TRUE;break;}  // Not a HEX char
           if((BYTE)((ByteHi << 4)|ByteLo) != ((PBYTE)ValueData)[idx]){fail=TRUE;break;}  
          }
         if(!fail){ctx->Status = STATUS_SUCCESS;DBGMSG("Binary Param found: %u", ValueLength);}
        }
         else if(wcsncmp(&ctx->Param->Buffer[1],(PWSTR)ValueData,(ValueLength/2))==0){ctx->Status = STATUS_SUCCESS;DBGMSG("String Param found: %S", ValueData);}    // WCHAR array                
      }
       else ctx->Status = STATUS_SUCCESS;  // Just checked key presense
     return STATUS_OBJECT_PATH_NOT_FOUND;     // Return some error to break enumeration process!
    }
  };
 
 BOOL hkcu = ((ValPath->Buffer[0] == 'H')&&(ValPath->Buffer[1] == 'K')&&(ValPath->Buffer[2] == 'C')&&(ValPath->Buffer[3] == 'U'));
 if(!Value)DBGMSG("Checking registry value '%wZ' on path '%wZ'", ValName, ValPath);
   else DBGMSG("Comparing registry value '%wZ' on path '%wZ' with '%wZ'", ValName, ValPath, Value);

 NTSTATUS  Status   = STATUS_SUCCESS;
 RTL_QUERY_REGISTRY_TABLE etbl[2];
 MemFillZero(&etbl, sizeof(etbl));  //RtlZeroMemory(&etbl,sizeof(etbl));

 ctx.Status    = STATUS_OBJECT_PATH_NOT_FOUND;
 ctx.Param     = Value;  
 etbl[0].Flags = RTL_QUERY_REGISTRY_REQUIRED;
 etbl[0].Name  = ValName->Buffer; 
 etbl[0].DefaultType  = REG_NONE;
 etbl[0].QueryRoutine = SCallback::QueryRoutine;

 if(hkcu)Status = RtlQueryRegistryValues(RTL_REGISTRY_USER,&ValPath->Buffer[5],&etbl[0],&ctx,NULL);
   else Status  = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,&ValPath->Buffer[0],&etbl[0],&ctx,NULL);
 if(!NT_SUCCESS(ctx.Status)){DBGMSG("The object check failed - %08X!",Status);return 1;}  // Alert! 
 DBGMSG("The object is OK.");
 return 0;
}  
//==============================================================================
UINT WorkCheckRegKey(PUNICODE_STRING KeyPath)
{
 NTSTATUS Status = STATUS_SUCCESS;
 BOOL hkcu       = ((KeyPath->Buffer[0] == 'H')&&(KeyPath->Buffer[1] == 'K')&&(KeyPath->Buffer[2] == 'C')&&(KeyPath->Buffer[3] == 'U'));
 DBGMSG("Checking registry key: %wZ", KeyPath);
 if(hkcu)Status = RtlCheckRegistryKey(RTL_REGISTRY_USER,&KeyPath->Buffer[5]);
   else Status  = RtlCheckRegistryKey(RTL_REGISTRY_ABSOLUTE,&KeyPath->Buffer[0]);
 if(!NT_SUCCESS(Status)){DBGMSG("The object check failed!");return 1;}  // Alert! 
 DBGMSG("The object is OK.");
 return 0;
}
//==============================================================================
UINT FindProcProtVirtMem(PUNICODE_STRING FullPath, PVOID Address, UINT Size)
{
 DBGMSG("Searching for 'ntdll.dll'...");    // TODO: Find it from ntdll.dll in x64/x32
 if(!IsModuleOnPathNtdll(FullPath))return 1; 
 
 PVOID ProcZwProtVirtMem = GetProcNtdllA(Address); 
 PVOID ProcZwClose       = GetProcNtdllB(Address);
 if(!ProcZwClose || !ProcZwProtVirtMem)return 1;
 UINT  DOffset           = RtlCompareMemory(ProcZwClose,ProcZwProtVirtMem,64); // Must return offset of ProcIndex
 DWORD IndexZwClose      = *((PDWORD)((PBYTE)ProcZwClose+DOffset));
 DWORD IndexProtVirtMem  = *((PDWORD)((PBYTE)ProcZwProtVirtMem+DOffset));
 DBGMSG("Index 'ProtectVirtualMemory' = %08X, Index 'ZwClose' = %08X",IndexProtVirtMem, IndexZwClose);
     
 /*DBGMSG("Searching for base of 'ntoskrnl.exe'...");
 PBYTE KernelBase = (PBYTE)((UINT)&ZwClose & ~0xFFF);  // x64 compatible
 while(!IsValidPEHeader(KernelBase))KernelBase -= 0x1000;  // This cycle MUST be ok
 DBGMSG("Base of 'ntoskrnl.exe' is %p",KernelBase);  */
                           
 PVOID ZwProcA = GetProcNtoskrnlA(); 
 PVOID ZwProcB = GetProcNtoskrnlB(); 
 if(!ZwProcA || !ZwProcB)return 1;
 UINT  POffset    = GetServiceIndexOffset(IndexZwClose, ZwProcB);  // Must return offset of ProcIndex
 if(!POffset)return 1;
 DWORD IndexProcA = *((PDWORD)((PBYTE)ZwProcA+POffset));
 DWORD IndexProcB = *((PDWORD)((PBYTE)ZwProcB+POffset));
 DBGMSG("IndexOffset = %u, ProcIndexA = %08X, ProcIndexB = %08X",POffset,IndexProcA,IndexProcB);   
      
 /*DBGMSG("Searching for 'KeServiceDescriptorTable'...");
 PVOID NtProcA       = &NtSetEvent;
 PVOID NtProcB       = &NtClose;
 PVOID *SrvDescTable = (PVOID*)KernelBase;
 for(;(SrvDescTable[IndexProcA] != NtProcA)||(SrvDescTable[IndexProcB] != NtProcB);SrvDescTable++);  */
          
 DBGMSG("Finding size of 'Zw' Entry...");
 PBYTE PAddress  = NULL;
 DWORD ProcIndex = 0;
 int   IOffset   = 0;
 if(IndexProcA < IndexProcB){PAddress = (PBYTE)ZwProcA;ProcIndex = IndexProcA;}
   else {PAddress = (PBYTE)ZwProcB;ProcIndex = IndexProcB;}
 for(;(IOffset < 128)&&(((PDWORD)PAddress)[0] != (ProcIndex+1));IOffset++,PAddress++);
 if(!IOffset)return 1; 
 UINT ZwEntrySize = IOffset-POffset; 
 DBGMSG("Entry size = %u",ZwEntrySize);      
             
 DBGMSG("Searching for 'ZwProtectVirtualMemory'...");  
 LONG_PTR Value    = (IndexProcB > IndexProtVirtMem)?(-(LONG_PTR)ZwEntrySize):(ZwEntrySize); // size of int on x64 = 4!
 PBYTE    ProcAddr = (PBYTE)ZwProcB;
 for(;*((PDWORD)(ProcAddr+POffset)) != IndexProtVirtMem;ProcAddr+=Value);
                      
 ProtVirtMem = (PVOID)~(ULONG_PTR)ProcAddr;   
 DBGMSG("ZwProtectVirtualMemory = %p",ProtVirtMem);         
 return 0;
}
//==============================================================================
UINT WorkCheckNewModule(PUNICODE_STRING ModPath, PUNICODE_STRING FullPath, PVOID Address, UINT Size)
{
 if(!IsModuleOnPath(ModPath, FullPath))return 1;
         
 SExApiAPC* NewAPC  = (SExApiAPC*)ExAllocatePoolWithTag(NonPagedPool,sizeof(SExApiAPC),'CPAK');
 NewAPC->ThreadId   = PsGetCurrentThreadId();
 NewAPC->ModuleBase = Address;
 NewAPC->ModuleSize = Size;

 NewAPC->FullImageName.Buffer = (PWSTR)&NewAPC->ModulePathBuf;
 NewAPC->FullImageName.Length = (FullPath->Length < sizeof(NewAPC->ModulePathBuf))?(FullPath->Length):(sizeof(NewAPC->ModulePathBuf)); 
 NewAPC->FullImageName.MaximumLength = sizeof(NewAPC->ModulePathBuf);           
 RtlCopyMemory(NewAPC->FullImageName.Buffer, &FullPath->Buffer[(FullPath->Length-NewAPC->FullImageName.Length)/sizeof(WCHAR)],NewAPC->FullImageName.Length);

 DBGMSG("Inserting an APC into current thread`s queue: Apc=%p, Thread=%08X",NewAPC,NewAPC->ThreadId); 
 KeInitializeApc(&NewAPC->apc,KeGetCurrentThread(),0,KernelApcCallback, NULL,NULL,UserMode,0);   // (PKNORMAL_ROUTINE)
 KeInsertQueueApc(&NewAPC->apc, 0, 0, 0);
 return 0;
}
//==============================================================================
VOID KernelApcCallback(IN struct _KAPC *Apc,IN OUT PKNORMAL_ROUTINE *NormalRoutine,IN OUT PVOID *NormalContext,IN OUT PVOID *SystemArgument1,IN OUT PVOID *SystemArgument2)
{
 SExApiAPC* Pars = (SExApiAPC*)Apc;
 DBGMSG("A kernel APC routine is called: Apc=%p, Thread=%08X",Apc,PsGetCurrentThreadId());
 DBGMSG("Target module: Base=%p, Size=%08X", Pars->ModuleBase,Pars->ModuleSize);
 DBGMSG("Previous Mode = %u",ExGetPreviousMode());

 UINT   FCtr    = 0;
 BOOL   ModX64  = IsValidModuleX64(Pars->ModuleBase);
 DWORD  XorVal, ICount;
 PDWORD DataBlk = GetParametersBlock(&XorVal, &ICount);
 for(UINT ictr=0;DataBlk && (ictr < ICount);ictr++)
  {  
   DWORD IType, ISize;
   WCHAR ParamA[512];        // Path       // Watch for '_chkstk'!
   if(GetEncryptedSubItem(0, ictr, 0, sizeof(ParamA), (PWSTR)&ParamA, XorVal, DataBlk, &IType, &ISize) < 0){DBGMSG("No Parameter [PATH]!");break;}  // Something wrong!
   UNICODE_STRING USParA;
   RtlInitUnicodeString(&USParA, (PWSTR)&ParamA);
   if(IType == CO_PROC)
    {
     WCHAR ParamB[256];  // Module Name   
     WCHAR ParamC[256];  // Proc A
     WCHAR ParamD[256];  // Proc B
     ANSI_STRING ModulName; 
     ANSI_STRING ProcNameA; 
     ANSI_STRING ProcNameB;
     UNICODE_STRING USParB;
     UNICODE_STRING USParC;
     UNICODE_STRING USParD;

     if(GetEncryptedSubItem(0, ictr, 1, sizeof(ParamB), (PWSTR)&ParamB, XorVal, DataBlk) < 0){DBGMSG("No Parameter [MNAME]!");continue;} ;  // Something wrong!
     if(GetEncryptedSubItem(0, ictr, 2, sizeof(ParamC), (PWSTR)&ParamC, XorVal, DataBlk) < 0){DBGMSG("No Parameter [PROCA]!");continue;} ;  // Something wrong!
     if(GetEncryptedSubItem(0, ictr, 3, sizeof(ParamD), (PWSTR)&ParamD, XorVal, DataBlk) < 0){DBGMSG("No Parameter [PROCB]!");continue;} ;  // Something wrong!
     RtlInitUnicodeString(&USParB, (PWSTR)&ParamB);
     RtlInitUnicodeString(&USParC, (PWSTR)&ParamC);
     RtlInitUnicodeString(&USParD, (PWSTR)&ParamD); 
     if(!IsModuleOnPath(&USParA, &Pars->FullImageName))continue;

     ModulName.Buffer        = (PCHAR)USParB.Buffer;    // ModName
     ModulName.Length        = USParB.Length/sizeof(WCHAR); 
     ModulName.MaximumLength = USParB.MaximumLength/sizeof(WCHAR);
     RtlUnicodeStringToAnsiString(&ModulName, &USParB, FALSE);

     ProcNameA.Buffer        = (PCHAR)USParC.Buffer;    // ProcA
     ProcNameA.Length        = USParC.Length/sizeof(WCHAR); 
     ProcNameA.MaximumLength = USParC.MaximumLength/sizeof(WCHAR);
     RtlUnicodeStringToAnsiString(&ProcNameA, &USParC, FALSE);

     ProcNameB.Buffer        = (PCHAR)USParD.Buffer;    // ProcB
     ProcNameB.Length        = USParD.Length/sizeof(WCHAR);
     ProcNameB.MaximumLength = USParD.MaximumLength/sizeof(WCHAR); 
     RtlUnicodeStringToAnsiString(&ProcNameB, &USParD, FALSE);

     DBGMSG("Exchanging imported API: Module='%Z', ProcA='%Z', ProcB='%Z'",&ModulName,&ProcNameA,&ProcNameB);                                            
     if(ModX64)ExchangeImportEntriesByName<PETYPE64>(&ModulName,&ProcNameA,&ProcNameB,Pars->ModuleBase);
       else ExchangeImportEntriesByName<PETYPE32>(&ModulName,&ProcNameA,&ProcNameB,Pars->ModuleBase);
    }    
  }

 ExFreePoolWithTag(Apc, 'CPAK');
}
//==============================================================================
template<typename T> UINT ExchangeImportEntriesByName(PSTRING ModuleName, PSTRING ProcNameA, PSTRING ProcNameB, PVOID ModuleBase)
{
 T *EntryAA,*EntryAB,*EntryBA,*EntryBB;

 EntryAA=EntryAB=EntryBA=EntryBB=NULL;
 DBGMSG("Searching for: <'%Z'>, '%Z'",ModuleName,ProcNameA);  
 if(GetEntryPointersForApiName<T>(ModuleName, ProcNameA, ModuleBase, &EntryAA, &EntryAB))return 1;
 DBGMSG("Searching for: <'%Z'>, '%Z'",ModuleName,ProcNameB);  
 if(GetEntryPointersForApiName<T>(ModuleName, ProcNameB, ModuleBase, &EntryBA, &EntryBB))return 1;
 DBGMSG("Exchanging: '%Z', '%Z'",ProcNameA,ProcNameB);  

 //DBGMSG("OriginalPrevMode= %u",ExGetPreviousMode());  // For testing only
 // These addresses are usually in the write-protected code section   // SEC_NO_CHANGE   MiProtectVirtualMemory  // ExGetPreviousMode // ZwProtectVirtualMemory
 if(ExchangeImportEntries<T>(EntryAA, EntryBA) && ExchangeImportEntries(EntryAB, EntryBB))return 1;
 return 0;
}
//==============================================================================
template<typename T> UINT ExchangeImportEntries(T* EnttryA, T* EnttryB)
{
 if(!ProtVirtMem){DBGMSG("Address of ZwProtectVirtualMemory is not yet found!");return 1;}
 NTSTATUS (WINAPI *ProtectVirtualMemory)(IN HANDLE ProcessHandle,IN OUT PVOID *BaseAddress,IN OUT PULONG_PTR NumberOfBytesToProtect,IN ULONG_PTR NewAccessProtection,OUT PULONG_PTR OldAccessProtection);
 ((ULONG_PTR*)&ProtectVirtualMemory)[0] = ~(ULONG_PTR)ProtVirtMem;

 DBGMSG("AddressA: %p, AddressB: %p",EnttryA, EnttryB);
 if(!EnttryA || !EnttryB)return 1;
 ULONG_PTR OldProt = 0;
 ULONG_PTR PSize   = (((EnttryA < EnttryB)?(EnttryB-EnttryA):(EnttryA-EnttryB))+1)*sizeof(T);  
 PVOID Addr        = (EnttryA < EnttryB)?(EnttryA):(EnttryB);
 DBGMSG("AllowingWriteMemory = %p, %08X",Addr,PSize);

 DBGMSG("Addr=%p, &Addr=%p; PSize=%p, &PSize=%p; &OldProt=%p",Addr, &Addr, PSize, &PSize, &OldProt);
 //__debugbreak();    // MiProtectVirtualMemory( Process, &Base, &Size, NewProtect, &OldProtect );

 NTSTATUS resa = ProtectVirtualMemory(NtCurrentProcess(),&Addr,&PSize,PAGE_EXECUTE_READWRITE,&OldProt);  // Can`t do this for KernelSpace  // Will Deadlock on any DLL (Patch only EXE of a new processes)
 DBGMSG("ProtectVirtualMemory RESULT = %u",resa);
 if(resa)return 1;     
 DBGMSG("BeforeValues = %p, %p",*EnttryA, *EnttryB);
 T UTemp  = *EnttryA; 
 *EnttryA = *EnttryB;   
 *EnttryB = UTemp;  
 DBGMSG("AfterValues = %p, %p",*EnttryA, *EnttryB);
 DBGMSG("RestoreMemProtection = %p, %08X",Addr,PSize);
 resa = ProtectVirtualMemory(NtCurrentProcess(),&Addr,&PSize,OldProt,&OldProt);
 DBGMSG("ProtectVirtualMemory RESULT = %u",resa);
 return 0;
}
//==============================================================================