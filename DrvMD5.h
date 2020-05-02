#pragma once

#ifndef DrvMD5H
#define DrvMD5H

#include "DrvDevice.h"
//------------------------------------------------------------------------------

#ifdef __alpha
typedef unsigned int UINT4;
#else
typedef unsigned long int UINT4;
#endif

typedef struct _MD5CONTEXT
{
 BOOL  UpCaseStr;
 BYTE  StrResultMD5[36];
 BYTE  BinResultMD5[16];
 BYTE  m_lpszBuffer[64];
 ULONG m_nCount[2];
 ULONG m_lMD5[4];
 BYTE  PADDING[64];   // [0] must be = 0x80
} MD5CONTEXT, *PMD5CONTEXT;


#define MD5_INIT_STATE_0 0x67452301
#define MD5_INIT_STATE_1 0xefcdab89
#define MD5_INIT_STATE_2 0x98badcfe
#define MD5_INIT_STATE_3 0x10325476

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y)  & (~z)))
#define H(x, y, z) ((x)  ^ (y)  ^ (z))
#define I(x, y, z) ((y)  ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) \
 {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a)  = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define GG(a, b, c, d, x, s, ac) \
 {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a)  = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define HH(a, b, c, d, x, s, ac) \
 {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a)  = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define II(a, b, c, d, x, s, ac) \
 {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
  (a)  = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }

//------------------------------------------------------------------------------
void MD5Init(PMD5CONTEXT mcon);
void MD5Final(PMD5CONTEXT mcon);
void MD5Update(unsigned char *inBuf, unsigned int inLen, PMD5CONTEXT mcon);
void GetMD5(unsigned char* pBuf, UINT nLength, PMD5CONTEXT mcon);

//------------------------------------------------------------------------------
#endif