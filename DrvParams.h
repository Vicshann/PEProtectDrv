#pragma once

#ifndef DrvParamsH
#define DrvParamsH

#include "DrvDevice.h"
#include "DrvFormatPE.h"
//------------------------------------------------------------------------------
// Encrypted item size = 2 DWORDs
#define IDELIM  "\t"
#define SIDELIM '\t'
#define CFGBLKFLAG 0xBD

enum ERMethod{rmDBGMSG=0,rmBSOD,rmSHUTDN,rmPFSIM,rmRETFIRMW,rmRKBPORT};
enum EGParams{gpCheckInterv=0,gpResMethod,gpChkOnStartup};

//------------------------------------------------------------------------------
PDWORD GetParametersBlock(PDWORD XorVal, PDWORD ICount, PDWORD GCount=NULL);
DWORD  GetGlobalParameter(UINT ParamIndex, DWORD XorVal, PDWORD DataBlk);
DWORD  GetGlobalParameter(UINT ParamIndex);
int    GetEncryptedSubItem(UINT ItemType, UINT Index, UINT SubIndex, UINT BufSize, PWSTR Buffer, DWORD XorVal, PDWORD DataBlk, PDWORD IType=NULL, PDWORD ISize=NULL);
//------------------------------------------------------------------------------
#endif