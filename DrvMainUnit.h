
#pragma once

#include "DrvFuncs.h"
//------------------------------------------------------------------------------
#define MAXDEVMAPPINGS 16
#define MAXMEMALLOCS   32

#define IOCTL_BASE           FILE_DEVICE_CUSTOM
#define IOCTL_FINDDEVICE     (IOCTL_BASE + 0) 
#define IOCTL_MAPDEVICEIO    (IOCTL_BASE + 1)      // Returns MEM struct
#define IOCTL_UNMAPDEVICEIO  (IOCTL_BASE + 2)  
#define IOCTL_FINDVAFORPHYS  (IOCTL_BASE + 3)              
#define IOCTL_ALLOCCONTIGMEM (IOCTL_BASE + 4)      // Returns MEM struct
#define IOCTL_FREECONTIGMEM  (IOCTL_BASE + 5)      
#define IOCTL_GETDEVCONFIG   (IOCTL_BASE + 6)      
#define IOCTL_SETDEVCONFIG   (IOCTL_BASE + 7)      
#define IOCTL_CREATEDEVDMA   (IOCTL_BASE + 8)      
#define IOCTL_REMOVEDEVDMA   (IOCTL_BASE + 9)      
#define IOCTL_READMEMORY     (IOCTL_BASE + 10)      
#define IOCTL_WRITEMEMORY    (IOCTL_BASE + 11)      
//------------------------------------------------------------------------------
extern "C" VOID     DriverUnload           (PDRIVER_OBJECT DriverObject);
extern "C" NTSTATUS DriverEntry            (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
extern "C" NTSTATUS AddDeviceProc          (PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysDeviceObject);
extern "C" NTSTATUS IrpMjPnpDispatch       (PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS IrpMjCreateDispatch    (PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS IrpMjCloseDispatch     (PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS IrpMjCleanupDispatch   (PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS IrpMjDevControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//------------------------------------------------------------------------------
#ifdef ALLOC_PRAGMA
//#pragma alloc_text (INIT, DriverEntry)
//#pragma alloc_text (PAGE, DriverUnload)
//#pragma alloc_text (PAGE, IrpMjCreateDispatch)
//#pragma alloc_text (PAGE, IrpMjCloseDispatch)
//#pragma alloc_text (PAGE, IrpMjDevControlDispatch)
#endif
//------------------------------------------------------------------------------
