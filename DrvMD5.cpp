//==============================================================================

#include "DrvMD5.h"

//==============================================================================
void MemClear(PVOID pData, UINT nLength)
{
 for(ULONG_PTR i=(nLength / sizeof(ULONG_PTR));i > 0;i--){((ULONG_PTR*)pData)[0]=0;pData = ((ULONG_PTR*)pData)+1;}
 for(ULONG_PTR i=(nLength % sizeof(ULONG_PTR));i > 0;i--){((BYTE*)pData)[0]=0;pData = ((BYTE*)pData)+1;}
}
//------------------------------------------------------------------------------
USHORT HexToChar(BYTE Value, BOOL UpCase)
{
 USHORT Result = 0;
 BYTE   Case   = UpCase ? 0x37 : 0x57;  // 'A' - 10
 for(int ctr=1;ctr >= 0;ctr--)
  {
   BYTE Tmp = (Value & 0x0F);
   if(Tmp < 0x0A)((BYTE*)&Result)[ctr] |= 0x30+Tmp;
	 else ((BYTE*)&Result)[ctr] |= Case+Tmp;
   Value  >>= 4;
  }
 return Result;
}
//------------------------------------------------------------------------------
void ByteToDWord(DWORD* Output, ULONG* Input, UINT nLength)
{
 UINT i=0;
 UINT j=0;
 for(; j < nLength; i++, j += 4)Output[i] = (ULONG)Input[j] | (ULONG)Input[j+1] << 8 | (ULONG)Input[j+2] << 16 | (ULONG)Input[j+3] << 24;
}
//------------------------------------------------------------------------------
void DWordToByte(unsigned char* Output, DWORD* Input, UINT nLength)
{
 UINT i = 0;
 UINT j = 0;
 for(; j < nLength; i++, j += 4)
  {
   Output[j]   = (UCHAR)(Input[i] & 0xff);
   Output[j+1] = (UCHAR)((Input[i] >> 8)  & 0xff);
   Output[j+2] = (UCHAR)((Input[i] >> 16) & 0xff);
   Output[j+3] = (UCHAR)((Input[i] >> 24) & 0xff);
  }
}
//------------------------------------------------------------------------------
void Transform(register UINT4 *buf,register UINT4 *in)
{
 register UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

#define S11 7
#define S12 12
#define S13 17
#define S14 22
 FF ( a, b, c, d, in[ 0], S11, 0xD76AA478L); 
 FF ( d, a, b, c, in[ 1], S12, 0xE8C7B756L); 
 FF ( c, d, a, b, in[ 2], S13, 0x242070DBL); 
 FF ( b, c, d, a, in[ 3], S14, 0xC1BDCEEEL); 
 FF ( a, b, c, d, in[ 4], S11, 0xF57C0FAFL); 
 FF ( d, a, b, c, in[ 5], S12, 0x4787C62AL); 
 FF ( c, d, a, b, in[ 6], S13, 0xA8304613L); 
 FF ( b, c, d, a, in[ 7], S14, 0xFD469501L); 
 FF ( a, b, c, d, in[ 8], S11, 0x698098D8L); 
 FF ( d, a, b, c, in[ 9], S12, 0x8B44F7AFL); 
 FF ( c, d, a, b, in[10], S13, 0xFFFF5BB1L); 
 FF ( b, c, d, a, in[11], S14, 0x895CD7BEL); 
 FF ( a, b, c, d, in[12], S11, 0x6B901122L); 
 FF ( d, a, b, c, in[13], S12, 0xFD987193L); 
 FF ( c, d, a, b, in[14], S13, 0xA679438EL); 
 FF ( b, c, d, a, in[15], S14, 0x49B40821L); 

#define S21 5
#define S22 9
#define S23 14
#define S24 20
 GG ( a, b, c, d, in[ 1], S21, 0xF61E2562L); 
 GG ( d, a, b, c, in[ 6], S22, 0xC040B340L); 
 GG ( c, d, a, b, in[11], S23, 0x265E5A51L); 
 GG ( b, c, d, a, in[ 0], S24, 0xE9B6C7AAL); 
 GG ( a, b, c, d, in[ 5], S21, 0xD62F105DL); 
 GG ( d, a, b, c, in[10], S22, 0x02441453L); 
 GG ( c, d, a, b, in[15], S23, 0xD8A1E681L); 
 GG ( b, c, d, a, in[ 4], S24, 0xE7D3FBC8L); 
 GG ( a, b, c, d, in[ 9], S21, 0x21E1CDE6L); 
 GG ( d, a, b, c, in[14], S22, 0xC33707D6L); 
 GG ( c, d, a, b, in[ 3], S23, 0xF4D50D87L); 
 GG ( b, c, d, a, in[ 8], S24, 0x455A14EDL); 
 GG ( a, b, c, d, in[13], S21, 0xA9E3E905L); 
 GG ( d, a, b, c, in[ 2], S22, 0xFCEFA3F8L); 
 GG ( c, d, a, b, in[ 7], S23, 0x676F02D9L); 
 GG ( b, c, d, a, in[12], S24, 0x8D2A4C8AL); 

#define S31 4
#define S32 11
#define S33 16
#define S34 23
 HH ( a, b, c, d, in[ 5], S31, 0xFFFA3942L); 
 HH ( d, a, b, c, in[ 8], S32, 0x8771F681L); 
 HH ( c, d, a, b, in[11], S33, 0x6D9D6122L); 
 HH ( b, c, d, a, in[14], S34, 0xFDE5380CL); 
 HH ( a, b, c, d, in[ 1], S31, 0xA4BEEA44L);
 HH ( d, a, b, c, in[ 4], S32, 0x4BDECFA9L); 
 HH ( c, d, a, b, in[ 7], S33, 0xF6BB4B60L); 
 HH ( b, c, d, a, in[10], S34, 0xBEBFBC70L); 
 HH ( a, b, c, d, in[13], S31, 0x289B7EC6L); 
 HH ( d, a, b, c, in[ 0], S32, 0xEAA127FAL); 
 HH ( c, d, a, b, in[ 3], S33, 0xD4EF3085L); 
 HH ( b, c, d, a, in[ 6], S34, 0x04881D05L);
 HH ( a, b, c, d, in[ 9], S31, 0xD9D4D039L); 
 HH ( d, a, b, c, in[12], S32, 0xE6DB99E5L); 
 HH ( c, d, a, b, in[15], S33, 0x1FA27CF8L); 
 HH ( b, c, d, a, in[ 2], S34, 0xC4AC5665L); 

#define S41 6
#define S42 10
#define S43 15
#define S44 21
 II ( a, b, c, d, in[ 0], S41, 0xF4292244L); 
 II ( d, a, b, c, in[ 7], S42, 0x432AFF97L); 
 II ( c, d, a, b, in[14], S43, 0xAB9423A7L); 
 II ( b, c, d, a, in[ 5], S44, 0xFC93A039L); 
 II ( a, b, c, d, in[12], S41, 0x655B59C3L); 
 II ( d, a, b, c, in[ 3], S42, 0x8F0CCC92L); 
 II ( c, d, a, b, in[10], S43, 0xFFEFF47DL); 
 II ( b, c, d, a, in[ 1], S44, 0x85845DD1L); 
 II ( a, b, c, d, in[ 8], S41, 0x6FA87E4FL); 
 II ( d, a, b, c, in[15], S42, 0xFE2CE6E0L); 
 II ( c, d, a, b, in[ 6], S43, 0xA3014314L); 
 II ( b, c, d, a, in[13], S44, 0x4E0811A1L); 
 II ( a, b, c, d, in[ 4], S41, 0xF7537E82L); 
 II ( d, a, b, c, in[11], S42, 0xBD3AF235L); 
 II ( c, d, a, b, in[ 2], S43, 0x2AD7D2BBL); 
 II ( b, c, d, a, in[ 9], S44, 0xEB86D391L); 

 buf[0] += a;
 buf[1] += b;
 buf[2] += c;
 buf[3] += d;
}
//------------------------------------------------------------------------------
void MD5Init(PMD5CONTEXT mcon)
{
 BOOL scase = mcon->UpCaseStr;
 MemClear(mcon, sizeof(MD5CONTEXT));
 mcon->UpCaseStr  = scase;
 mcon->PADDING[0] = 0x80;

 mcon->m_lMD5[0]  = MD5_INIT_STATE_0;
 mcon->m_lMD5[1]  = MD5_INIT_STATE_1;
 mcon->m_lMD5[2]  = MD5_INIT_STATE_2;
 mcon->m_lMD5[3]  = MD5_INIT_STATE_3;
}
//------------------------------------------------------------------------------
void MD5Update(unsigned char *inBuf, unsigned int inLen, PMD5CONTEXT mcon)
{
 register int i, ii;
 int   mdi;
 UINT4 in[16];

 mdi = (int)((mcon->m_nCount[0] >> 3) & 0x3F);

 if((mcon->m_nCount[0] + ((UINT4)inLen << 3)) < mcon->m_nCount[0])mcon->m_nCount[1]++;
 mcon->m_nCount[0] += ((UINT4)inLen << 3);
 mcon->m_nCount[1] += ((UINT4)inLen >> 29);

 while (inLen--)
  {
   mcon->m_lpszBuffer[mdi++] = *inBuf++;
   if (mdi == 0x40) 
    {
	 for (i = 0, ii = 0; i < 16; i++, ii += 4)in[i] = (((UINT4)mcon->m_lpszBuffer[ii+3]) << 24) |(((UINT4)mcon->m_lpszBuffer[ii+2]) << 16) |(((UINT4)mcon->m_lpszBuffer[ii+1]) << 8) |((UINT4)mcon->m_lpszBuffer[ii]);
	 Transform (mcon->m_lMD5, in);
     mdi = 0;
    }
  }
}
//------------------------------------------------------------------------------
void MD5Final(PMD5CONTEXT mcon)
{
 unsigned char bits[8];
 int           nIndex;
 unsigned int  nPadLen;
 const    int  nMD5Size = 16;
 USHORT chr;
 int    i;

 DWordToByte(bits, mcon->m_nCount, 8);

 nIndex  = (int)((mcon->m_nCount[0] >> 3) & 0x3f);
 nPadLen = (nIndex < 56) ? (56 - nIndex) : (120 - nIndex);
 MD5Update (mcon->PADDING, nPadLen, mcon);

 MD5Update(bits, 8, mcon);
 DWordToByte(&mcon->BinResultMD5[0], mcon->m_lMD5, nMD5Size);
 for(i=0; i < nMD5Size; i++)
  {
   chr = HexToChar(mcon->BinResultMD5[i],mcon->UpCaseStr);
   mcon->StrResultMD5[(i*2)]   = ((PBYTE)&chr)[0];
   mcon->StrResultMD5[(i*2)+1] = ((PBYTE)&chr)[1];
  }
}
//------------------------------------------------------------------------------
void GetMD5(unsigned char* pBuf, UINT nLength, PMD5CONTEXT mcon)
{
 MD5Init(mcon);
 MD5Update(pBuf, nLength, mcon);
 MD5Final(mcon);
}
//------------------------------------------------------------------------------

