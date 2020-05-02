#pragma once

#include "DrvCommon.h" // place it before <ntddk.h> to avoid warnings
#include "DrvUtils.h"
//#include "klist.h"
//#include "kresreq.h"
//#include "kaddress.h"
//------------------------------------------------------------------------------
 #define DRIVERNAME  "KDMAIDevice"     
 #define DEVICEPATH  "\\Device\\"
 #define SYMLNKPATH  "\\DosDevices\\"

#define EXCLUSIVEOPEN  FALSE    // Set to false, if the driver can handle accesses from a multiple processes      
#define FILE_DEVICE_CUSTOM   0x00008000







//------------------------------------------------------------------------------
