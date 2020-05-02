//=============================================================================
#include "DrvMainUnit.h"

// Link with kernel: hal.lib  ntoskrnl.lib

#pragma comment(linker,"/merge:.rdata=.data")
//#pragma comment(linker,"/merge:.pdata=.data")   // x64 only
#pragma comment(linker, "/section:.data,rw")

//#pragma comment(linker,"/merge:INIT=.text")    // Does not works. Compile driver as DLL instead
//#pragma comment(linker, "/section:.text,rwe")

ULONG_PTR KernelBase = 0;
//=============================================================================
// For Pnp drivers called only on first load!
//
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{    
 KernelBase = ~GetKernelBase(DriverObject);  
 DBGMSG("Return = %p, KernelBase = %p",((PVOID*)&DriverObject)[-1], ~KernelBase);  
   
                                  
// __debugbreak();     KeLastBranchMSR
/*     
C:\Windows\system32\ntkrnlmp.exe

//0xFFFFF800`01819000
0xFFFFF800`0184d000  >>> 0xFFFFF800`01e36000
0x5E9000 bytes

Fault: 0xFFFFF800`019F1000

MmSecureVirtualMemory
ProbeForRead
ProbeForWrite
*/
/*       
 PBYTE KAddr = (PBYTE)0xFFFFF8000184d000;
 UINT  KSize = 0x5E9000;   //
 volatile BYTE Val = 0;
 PVOID res = MmLockPagableDataSection((PVOID)0xFFFFF800019F1000);
 DBGMSG("LockResult = %p",res);
 //for(UINT base=0;base < KSize;base+=0x1000)Val = (KAddr+base)[0];
  */

 DriverObject->DriverUnload                         = DriverUnload;
 DriverObject->DriverExtension->AddDevice           = AddDeviceProc;
 DriverObject->MajorFunction[IRP_MJ_PNP]            = IrpMjPnpDispatch;
 //DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpMjCreateDispatch;
 //DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpMjCloseDispatch; 
 //DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = IrpMjCleanupDispatch; 
 //DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpMjDevControlDispatch;
 DBGMSG("Callbacks are assigned.");     

 // No real device, - only one instance will be used      
 NTSTATUS Status = DeclareCustomDevice(DriverObject,sizeof(DEVICE_EXTENSION),FALSE,FALSE); 
 DBGMSG("Device created, result=%u.",Status);                                                                                              
 if(!NT_SUCCESS(Status))return Status;
                                            
 DBGMSG("Device Characteristics = %08X",DriverObject->DeviceObject->Characteristics);  // FILE_CHARACTERISTIC_PNP_DEVICE
 PDEVICE_EXTENSION DevExt = (PDEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;
 DevExt->doDriver = DriverObject; 
 ExInitializeFastMutex(&DevExt->MFMutex);  // Really can be called multiple times? (While no one is waiting on it, of course)  
 Status = ProcessDeviceInitialization(DriverObject->DeviceObject); // Or before? 
 if(!NT_SUCCESS(Status))return Status;
 DBGMSG("Successfully initialized.");           
 return STATUS_SUCCESS; 
}
//------------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
 if(!DriverObject->DeviceObject){DBGMSG("No DeviceObject present!");return;}
 PDEVICE_EXTENSION DevExt = (PDEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;   // DeviceObject may not be yet created!

 DBGMSG("Uninitializing...");     
 DevExt->FreeResources();
 DBGMSG("Finished");
}
//------------------------------------------------------------------------------
NTSTATUS AddDeviceProc(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysDeviceObject)
{
 PDEVICE_OBJECT    DeviceObject = DriverObject->DeviceObject;
 PDEVICE_EXTENSION DevExt       = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;  // Must be already created
 DevExt->dePhysDev = PhysDeviceObject;
 DevExt->deNextDev = IoAttachDeviceToDeviceStack(DriverObject->DeviceObject, PhysDeviceObject);
 DBGMSG("IoAttachDeviceToDeviceStack, result=%08X.",DevExt->deNextDev);
 if(!DevExt->deNextDev)return STATUS_UNSUCCESSFUL;  // {IoDeleteSymbolicLink(&DevExt->deSymLink);IoDeleteDevice(DeviceObject);}
 
 // Копирование флагов устройства из устройства ниже по стеку.
 DeviceObject->Flags |= (!(DevExt->deNextDev->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE | DO_POWER_INRUSH)));
 DeviceObject->Flags &= ~(DO_POWER_PAGABLE | DO_POWER_INRUSH); 
 DeviceObject->Flags &= ~(DO_BUFFERED_IO | DO_DIRECT_IO); 
 DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;   // !!!!!!  Do not forget! 
 DeviceObject->Flags |= DO_DIRECT_IO|DO_POWER_PAGABLE;     // All WDM must set DO_POWER_PAGABLE

 ExInitializeFastMutex(&DevExt->MFMutex);
 DBGMSG("Successfully initialized.");     
 return STATUS_SUCCESS;
}
//=============================================================================
//
// IRP_MN_FILTER_RESOURCE_REQUIREMENTS
// IRP_MN_QUERY_RESOURCE_REQUIREMENTS  - Bus filter drivers can handle this request. Function and filter drivers do not handle this IRP.
//
NTSTATUS IrpMjPnpDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
 NTSTATUS           Status   = STATUS_SUCCESS;
 PDEVICE_EXTENSION  DevExt   = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
 PIO_STACK_LOCATION pNewIRPCell;
 PCM_RESOURCE_LIST  resList;
 USHORT res;
 UCHAR i;
    
 //ExAcquireFastMutex(&DevExt->MFMutex);  // NOT IN IrpMjPnpDispatch
 switch(IrpStack->MinorFunction)
  {
   case IRP_MN_START_DEVICE:
    {
     DBGMSG("Processing IRP_MN_START_DEVICE message.");
     Status = SendIrpSynchronously(DevExt->deNextDev, Irp);
     if(NT_SUCCESS(Status))Status = ProcessDeviceInitialization(DeviceObject); // Or before?
    }
     break;
   case IRP_MN_QUERY_STOP_DEVICE:
    {
     DBGMSG("Processing IRP_MN_QUERY_STOP_DEVICE message.");
     Irp->IoStatus.Status = STATUS_SUCCESS;
     IoSkipCurrentIrpStackLocation (Irp);
     Status = IoCallDriver(DevExt->deNextDev, Irp);
     return Status;
    }
     break;
   /*case IRP_MN_CANCEL_STOP_DEVICE:
    {
     Status = SendIrpSynchronously(DevExt->deNextDev, Irp);
    }
     break;*/
   case IRP_MN_STOP_DEVICE:
    {
     DBGMSG("Processing IRP_MN_STOP_DEVICE message.");
     Irp->IoStatus.Status = STATUS_SUCCESS;
     IoSkipCurrentIrpStackLocation (Irp);
     Status = IoCallDriver(DevExt->deNextDev, Irp);
     return Status;
    }
     break;
   case IRP_MN_QUERY_REMOVE_DEVICE:
    {
     DBGMSG("Processing IRP_MN_QUERY_REMOVE_DEVICE message.");
     Irp->IoStatus.Status = STATUS_SUCCESS;
     IoSkipCurrentIrpStackLocation (Irp);
     Status = IoCallDriver(DevExt->deNextDev, Irp);
     return Status;
    }
     break;
   /*case IRP_MN_CANCEL_REMOVE_DEVICE:
    {
     Status = SendIrpSynchronously(DevExt->deNextDev, Irp);
    }
     break; */
   case IRP_MN_SURPRISE_REMOVAL:
    {
     DBGMSG("Processing IRP_MN_SURPRISE_REMOVAL message.");
     Irp->IoStatus.Status = STATUS_SUCCESS;
     IoSkipCurrentIrpStackLocation (Irp);
     Status = IoCallDriver(DevExt->deNextDev, Irp);
     return Status;
    }
     break;
   case IRP_MN_REMOVE_DEVICE:
    {
     DBGMSG("Processing IRP_MN_REMOVE_DEVICE message.");
     Irp->IoStatus.Status = STATUS_SUCCESS;
     IoSkipCurrentIrpStackLocation (Irp);
     Status = IoCallDriver (DevExt->deNextDev, Irp);
     DevExt->FreeResources();  // Deallocates memory of DevExt 
     return Status;
    }
     break;
   default:
    {
     DBGMSG("Passing the PnP message %u to a lower driver.",IrpStack->MinorFunction);
     IoSkipCurrentIrpStackLocation (Irp);
     Status = IoCallDriver(DevExt->deNextDev, Irp);
     return Status;
    }
  }

 Irp->IoStatus.Status      = Status;
 Irp->IoStatus.Information = 0;   

 //ExReleaseFastMutex(&DevExt->MFMutex);     // NOT IN IrpMjPnpDispatch
 IoCompleteRequest(Irp, IO_NO_INCREMENT);         
 return Status;
}
//------------------------------------------------------------------------------
NTSTATUS IrpMjCreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
 NTSTATUS           Status   = STATUS_SUCCESS;
 PDEVICE_EXTENSION  DevExt   = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

 DBGMSG("Opening driver`s Handle");     
 ExAcquireFastMutex(&DevExt->MFMutex);

 Irp->IoStatus.Status      = Status;
 Irp->IoStatus.Information = 0;
                                     
 ExReleaseFastMutex(&DevExt->MFMutex);
 IoCompleteRequest(Irp, IO_NO_INCREMENT);
 DBGMSG("Finished");     
 return Status;
}                         
//------------------------------------------------------------------------------
// The IRP_MJ_CLOSE request is not sent in the context of the process that closed the file object handle. 
// If the driver must release process-specific resources, such as user memory, that the driver previously locked or 
// mapped, it must do so in response to an IRP_MJ_CLEANUP request.
//
NTSTATUS IrpMjCloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
 NTSTATUS           Status   = STATUS_SUCCESS;
 PDEVICE_EXTENSION  DevExt   = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

 DBGMSG("Closing driver`s Handle...");   
 ExAcquireFastMutex(&DevExt->MFMutex);

 Irp->IoStatus.Status      = Status;
 Irp->IoStatus.Information = 0; 

 ExReleaseFastMutex(&DevExt->MFMutex);
 IoCompleteRequest(Irp, IO_NO_INCREMENT);   // CompleteIrp(Irp,STATUS_SUCCESS,0);
 DBGMSG("Finished");     
 return Status;      
}
//------------------------------------------------------------------------------
NTSTATUS IrpMjCleanupDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
 NTSTATUS           Status   = STATUS_SUCCESS;
 PDEVICE_EXTENSION  DevExt   = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

 DBGMSG("Releasing resources...");    
 ExAcquireFastMutex(&DevExt->MFMutex);

 Irp->IoStatus.Status      = Status;
 Irp->IoStatus.Information = 0; 

 ExReleaseFastMutex(&DevExt->MFMutex);
 IoCompleteRequest(Irp, IO_NO_INCREMENT);   // CompleteIrp(Irp,STATUS_SUCCESS,0);
 DBGMSG("Finished");     
 return Status;      
}
//------------------------------------------------------------------------------
NTSTATUS IrpMjDevControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
 IoCtrlCode CtlCode;
 NTSTATUS   StsResult = STATUS_SUCCESS;
 ULONG      CmdResult = 0;

 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
 PDEVICE_EXTENSION  DevExt   = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

 CtlCode.dwControlCode  = IrpStack->Parameters.DeviceIoControl.IoControlCode;
 DevExt->InputBufLen    = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
 DevExt->ResultBufLen   = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

// Both METHOD_IN_DIRECT and METHOD_OUT_DIRECT are handled the same way in the driver. 
// They differ only in the access rights required for the user-mode buffer. METHOD_IN_DIRECT 
// needs read access; METHOD_OUT_DIRECT needs read and write access. With both of these methods, 
// the I/O Manager provides a kernel-mode copy buffer (at AssociatedIrp.SystemBuffer) for the input 
// data and an MDL for the output data buffer.

 //ExAcquireFastMutex(&DevExt->MFMutex);     // Slow?
 DevExt->LastIrp = Irp;
 switch(CtlCode.TransferType)
  {
   case METHOD_NEITHER:          // Pointerf to User Space buffers
     //DBGMSG("METHOD_NEITHER");
     DevExt->InputBuffer  = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer; 
     DevExt->ResultBuffer = Irp->UserBuffer;
     break;
   case METHOD_BUFFERED:         // Input and output buffers are combined by the system.
     //DBGMSG("METHOD_BUFFERED");
     DevExt->InputBuffer  = DevExt->ResultBuffer = Irp->AssociatedIrp.SystemBuffer;  // Untested!!!  
     break;
   case METHOD_IN_DIRECT:
   case METHOD_OUT_DIRECT:
     //DBGMSG("METHOD_DIRECT");
     DevExt->InputBuffer  = Irp->AssociatedIrp.SystemBuffer;
     DevExt->ResultBuffer = MmGetMdlVirtualAddress(Irp->MdlAddress);  // !!!!!! This represents the output buffer, this buffer can actually be used as either an input buffer or an output buffer
     break;
  }                          
                               
 //DBGMSG("Executing the control code: %u",CtlCode.FunctionCode);
 CmdResult = DevExt->ResultBufLen; 
 switch(CtlCode.dwControlCode)   //FunctionCode)
  { 
		default:
			// Unrecognized IOCTL request
            DBGMSG("No processing for this code exist!");  
			StsResult = STATUS_INVALID_PARAMETER;
			break;
  }
    
 //DBGMSG("Operation result=%u, status=%08X",CmdResult,StsResult);
 Irp->IoStatus.Status      = StsResult;    
 Irp->IoStatus.Information = CmdResult;

 //ExReleaseFastMutex(&DevExt->MFMutex);   // Slow?
 IoCompleteRequest(Irp, IO_NO_INCREMENT);
 return StsResult;
}
//=============================================================================

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------

//=============================================================================
