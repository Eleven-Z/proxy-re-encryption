// The JHU-MIT Proxy Re-encryption Library (PRL)
//
// proxylib_utilities.cpp: Contains utility routines used by the
// proxy re-encryption algorithms.
//
// ================================================================
// 	
// Copyright (c) 2007, Matthew Green, Giuseppe Ateniese, Kevin Fu,
// Susan Hohenberger.  All rights reserved.
//
// This Agreement, effective as of March 1, 2007 is between the
// Massachusetts Institute of Technology ("MIT"), a non-profit
// institution of higher education, and you (YOU).
//
// WHEREAS, M.I.T. has developed certain software and technology
// pertaining to M.I.T. Case No. 11977, "Unidirectional Proxy
// Re-Encryption," by Giuseppe Ateniese, Kevin Fu, Matt Green and Susan
// Hohenberger (PROGRAM); and
// 
// WHEREAS, M.I.T. is a joint owner of certain right, title and interest
// to a patent pertaining to the technology associated with M.I.T. Case
// No. 11977 "Unidirectional Proxy Re-Encryption," (PATENTED INVENTION");
// and
// 
// WHEREAS, M.I.T. desires to aid the academic and non-commercial
// research community and raise awareness of the PATENTED INVENTION and
// thereby agrees to grant a limited copyright license to the PROGRAM for
// research and non-commercial purposes only, with M.I.T. retaining all
// ownership rights in the PATENTED INVENTION and the PROGRAM; and
// 
// WHEREAS, M.I.T. agrees to make the downloadable software and
// documentation, if any, available to YOU without charge for
// non-commercial research purposes, subject to the following terms and
// conditions.
// 
// THEREFORE:
// 
// 1.  Grant.
// 
// (a) Subject to the terms of this Agreement, M.I.T. hereby grants YOU a
// royalty-free, non-transferable, non-exclusive license in the United
// States for the Term under the copyright to use, reproduce, display,
// perform and modify the PROGRAM solely for non-commercial research
// and/or academic testing purposes.
// 
// (b) MIT hereby agrees that it will not assert its rights in the
// PATENTED INVENTION against YOU provided that YOU comply with the terms
// of this agreement.
// 
// (c) In order to obtain any further license rights, including the right
// to use the PROGRAM or PATENTED INVENTION for commercial purposes, YOU
// must enter into an appropriate license agreement with M.I.T.
// 
// 2.  Disclaimer.  THE PROGRAM MADE AVAILABLE HEREUNDER IS "AS IS",
// WITHOUT WARRANTY OF ANY KIND EXPRESSED OR IMPLIED, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE, NOR REPRESENTATION THAT THE PROGRAM DOES NOT
// INFRINGE THE INTELLECTUAL PROPERTY RIGHTS OF ANY THIRD PARTY. MIT has
// no obligation to assist in your installation or use of the PROGRAM or
// to provide services or maintenance of any type with respect to the
// PROGRAM.  The entire risk as to the quality and performance of the
// PROGRAM is borne by YOU.  YOU acknowledge that the PROGRAM may contain
// errors or bugs.  YOU must determine whether the PROGRAM sufficiently
// meets your requirements.  This disclaimer of warranty constitutes an
// essential part of this Agreement.
// 
// 3. No Consequential Damages; Indemnification.  IN NO EVENT SHALL MIT
// BE LIABLE TO YOU FOR ANY LOST PROFITS OR OTHER INDIRECT, PUNITIVE,
// INCIDENTAL OR CONSEQUENTIAL DAMAGES RELATING TO THE SUBJECT MATTER OF
// THIS AGREEMENT.
// 
// 4. Copyright.  YOU agree to retain M.I.T.'s copyright notice on all
// copies of the PROGRAM or portions thereof.
// 
// 5. Export Control.  YOU agree to comply with all United States export
// control laws and regulations controlling the export of the PROGRAM,
// including, without limitation, all Export Administration Regulations
// of the United States Department of Commerce.  Among other things,
// these laws and regulations prohibit, or require a license for, the
// export of certain types of software to specified countries.
// 
// 6. Reports, Notices, License Request.  Reports, any notice, or
// commercial license requests required or permitted under this Agreement
// shall be directed to:
// 
// Director
// Massachusetts Institute of Technology Technology
// Licensing Office, Rm NE25-230 Five Cambridge Center, Kendall Square
// Cambridge, MA 02142-1493						
// 
// 7.  General.  This Agreement shall be governed by the laws of the
// Commonwealth of Massachusetts.  The parties acknowledge that this
// Agreement sets forth the entire Agreement and understanding of the
// parties as to the subject matter.

#include <iostream>
#include <fstream>
#include <cstring>
#include "ecn.h"
#include "zzn2.h"

using namespace std;

#include "proxylib_api.h"
#include "proxylib.h"
#ifdef BENCHMARKING
#include "benchmark.h"
#endif

#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

BOOL gDebugPrint = TRUE;
Miracl precision(32,0);

//
// Library initialization
//

BOOL 
initLibrary(BOOL selfseed, char *seedbuf, int bufsize)
{
  long seed;

  // If we're seeding ourself, try to do it
  if (selfseed == TRUE) {
    char entropy[NK * sizeof(mr_unsign32)];

    // Try to seed from system entropy
    if (entropyCollect(entropy, NK * sizeof(mr_unsign32)) == FALSE) {
      PRINT_DEBUG_STRING("Self-seeding failed");
      return FALSE;
    } else {
      bufrand(entropy, NK * sizeof(mr_unsign32));
      return TRUE;
    }
  }

  // Otherwise, try to seed from the buffer provided
  if (seedbuf != NULL && bufsize >= 4) {
    bufrand(seedbuf, bufsize);
    return TRUE;
  }

#if 0
  // If all else fails, talk to the user (this should go away)
  cout << "Enter 9 digit random number seed  = ";
  cin >> seed;
  irand(seed);
#endif

  return FALSE;
}

// encodePlaintextAsBig()
//
// Encodes a binary buffer as a Big type.  This is used to permit
// encryption of arbitrary binary strings.  Should not be confused
// with charToBig(), which is used to deserialize Big structures.
// Returns FALSE if the message is too long to fit.

BOOL
encodePlaintextAsBig(CurveParams &params,
		     char *message, int messageLen, Big &msg)
{
  // First, determine if the message is too large.
  if ((messageLen << 3) > params.maxPlaintextSize()) {
    // Message too long
    msg = (Big)0;
    return FALSE;
  }

  // Next, encode the plaintext as a Big
  msg = from_binary(messageLen, message);
  return TRUE;
}

// decodePlaintextFromBig()
//
// Decodes a binary buffer from a Big type.  This is used to permit
// edecryption of arbitrary binary strings.  Should not be confused
// with bigToChar(), which is used to deserialize Big structures.
// Returns FALSE if there is an error.

BOOL
decodePlaintextFromBig(CurveParams &params,
		     char *message, int maxMessage, 
		     int *messageLen, Big &msg)
{
  // First, determine if the message is too large.
  if ((maxMessage << 3) < bits(msg)) {
    // Not enough room to decode message
    *messageLen = 0;
    return FALSE;
  }
  
  // Next, encode the plaintext as a Big
  *messageLen = bits(msg) / 8;
  to_binary(msg, *messageLen, message, FALSE);
  return TRUE;
}

#if 0
//
// Parameter file read/write
//

BOOL ReadParamsFile(char *paramFile, CurveParams &params)
{
  Big x, y;
  ifstream common(paramFile);
  miracl *mip=&precision;
  
  common >> params.bits;
  mip->IOBASE=16;
  common >> params.p >> params.q;
  params.qsquared = pow(params.q, 2);
  
  common >> x >> y;
    
#ifdef AFFINE
    ecurve(0,1,params.p,MR_AFFINE);
#endif
#ifdef PROJECTIVE
    ecurve(0,1,params.p,MR_PROJECTIVE);
#endif

    params.P.set(x,y);

    common >> x >> y;
    params.cube.set(x,y);
    mip->IOBASE=10;
    cout << "Cube: " << params.cube << endl;
    mip->IOBASE=16;

    common >> x >> y;
    params.Z.set(x, y);
    mip->IOBASE=10;
    cout << "Z: " << params.Z << endl;
    mip->IOBASE=16;

    return true;
}

//
// Public key file reading
//

BOOL ReadPublicKeyFile(char *filename, ProxyPK &pubkey)
{
  Big x, y;
  ifstream keyfile(filename);
  miracl *mip=&precision;
  
  mip->IOBASE=16;
  keyfile >> x >> y;
  //cout << "ZPub.x=" << x << ", ZPub.y=" << y << endl;
  pubkey.Zpub1.set(x, y);

  keyfile >> x >> y;
  pubkey.Ppub2.set(x, y);

  return true;
}

//
// Secret key file reading
//

BOOL ReadSecretKeyFile(char *filename, ProxySK &secret)
{
  ifstream keyfile(filename);
  miracl *mip=&precision;
  
  mip->IOBASE=16;
  keyfile >> secret.s1 >> secret.s2;

  return true;
}

#endif //0
  
//
// Hash functions
// 

Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha sh;

    shs_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs_process(&sh,string[i]);
    }
    shs_hash(&sh,s);
    p=get_modulus();
    h=1; j=0; i=1;
    forever
    {
        h*=256; 
        if (j==HASH_LEN)  {h+=i++; j=0;}
        else         h+=s[j++];
        if (h>=p) break;
    }
    h%=p;
    return h;
}

int H2(ZZn2 x,char *s)
{ // Hash an Fp2 to an n-byte string s[.]. Return n
    sha sh;
    Big a,b;
    int m;

    shs_init(&sh);
    x.get(a,b);
    while (a>0)
    {
        m=a%256;
        shs_process(&sh,m);
        a/=256;
    }
    while (b>0)
    {
        m=b%256;
        shs_process(&sh,m);
        b/=256;
    }
    shs_hash(&sh,s);

    return HASH_LEN;
}

Big H3(char *x1,char *x2)
{
    sha sh;
    char h[HASH_LEN];
    Big a;
    int i;

    shs_init(&sh);
    for (i=0;i<HASH_LEN;i++)
        shs_process(&sh,x1[i]);
    for (i=0;i<HASH_LEN;i++)
        shs_process(&sh,x2[i]);
    shs_hash(&sh,h);
    a=from_binary(HASH_LEN,h);
    return a;
}

void H4(char *x,char *y)
{ // hashes y=h(x)
    int i;
    sha sh;
    shs_init(&sh);
    for (i=0;i<HASH_LEN;i++)
        shs_process(&sh,x[i]);
    shs_hash(&sh,y);
}
   
//
// Given y, get x=(y^2-1)^(1/3) mod p (from curve equation)
//

Big getx(Big y)
{
    Big p=get_modulus();
    Big t=modmult(y+1,y-1,p);   // avoids overflow
    return pow(t,(2*p-1)/3,p);
}
 
//
// MapToPoint
//

ECn map_to_point(char *ID)
{
    ECn Q;
    Big x0,y0=H1(ID);
    x0=getx(y0);

    Q.set(x0,y0);

    return Q;
}

#define SCOTT

//
// Tate Pairing Code
//
// Extract ECn point in internal ZZn format
//

void extract(ECn& A,ZZn& x,ZZn& y)
{ 
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
}

void extract(ECn& A,ZZn& x,ZZn& y,ZZn& z)
{ 
    big t;
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
    t=(A.get_point())->Z;
    if (A.get_status()!=MR_EPOINT_GENERAL) z=1;
    else                                   z=t;
}

//
// Line from A to destination C. Let A=(x,y)
// Line Y-slope.X-c=0, through A, so intercept c=y-slope.x
// Line Y-slope.X-y+slope.x = (Y-y)-slope.(X-x) = 0
// Now evaluate at Q -> return (Qy-y)-slope.(Qx-x)
//

ZZn2 line(ECn& A,ECn& C,ZZn& slope,ZZn2& Qx,ZZn2& Qy)
{ 
    ZZn2 n=Qx,w=Qy;
    ZZn x,y,z,t;
#ifdef AFFINE
    extract(A,x,y);
    n-=x; n*=slope;            // 2 ZZn muls
    w-=y; n-=w;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    x*=z; t=z; z*=z; z*=t;          
    n*=z; n-=x;                // 9 ZZn muls
    w*=z; w-=y; 
    extract(C,x,y,z);
    w*=z; n*=slope; n-=w;                     
#endif
    return n;
}

#ifndef SCOTT

//
// Vertical line through point A
//

ZZn2 vertical(ECn& A,ZZn2& Qx)
{
    ZZn2 n=Qx;
    ZZn x,y,z;
#ifdef AFFINE
    extract(A,x,y);
    n-=x;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    z*=z;                    
    n*=z; n-=x;                // 3 ZZn muls
#endif
    return n;
}

#endif

//
// Add A=A+B  (or A=A+A) 
// Bump up num and denom
//
// AFFINE doubling     - 12 ZZn muls, plus 1 inversion
// AFFINE adding       - 11 ZZn muls, plus 1 inversion
//
// PROJECTIVE doubling - 26 ZZn muls
// PROJECTIVE adding   - 34 ZZn muls
//


void g(ECn& A,ECn& B,ZZn2& Qx,ZZn2& Qy,ZZn2& num)
{
    ZZn  lam,mQy;
    ZZn2 d,u;
    big ptr;
    ECn P=A;

// Evaluate line from A
    ptr=A.add(B);

#ifndef SCOTT
    if (A.iszero())   { u=vertical(P,Qx); d=1; }
    else
    {
#endif
        if (ptr==NULL) u=1;
        else 
        {
            lam=ptr;
            u=line(P,A,lam,Qx,Qy);
        }
#ifndef SCOTT
        d=vertical(A,Qx);
    }

    num*=(u*conj(d));    // 6 ZZn muls  
#else
// denominator elimination!
    num*=u;
#endif
}

//
// Tate Pairing 
//

BOOL fast_tate_pairing(ECn& P,ZZn2& Qx,ZZn2& Qy,Big& q,ZZn2& res)
{ 
    int i,nb;
    Big n,p;
    ECn A;


// q.P = 2^17*(2^142.P +P) + P

    res=1;
    A=P;    // reset A

#ifdef SCOTT
// we can avoid last iteration..
    n=q-1;
#else
    n=q;
#endif
    nb=bits(n);

    for (i=nb-2;i>=0;i--)
    {
        res*=res;         
        g(A,A,Qx,Qy,res); 
        if (bit(n,i))
            g(A,P,Qx,Qy,res);       
    }

#ifdef SCOTT
    if (A!=-P || res.iszero()) return FALSE;
#else
    if (!A.iszero()) return FALSE;
#endif

    p=get_modulus();         // get p
    res= pow(res,(p+1)/q);   // raise to power of (p^2-1)/q
    res=conj(res)/res;
    if (res.isunity()) return FALSE;
    return TRUE;   
}

//
// ecap(.) function - apply distortion map
//
// Qx is in ZZn if SCOTT is defined. Qy is in ZZn if SCOTT is not defined. 
// This can be exploited for some further optimisations. 
//

BOOL ecap(ECn& P,ECn& Q,Big& order,ZZn2& cube,ZZn2& res)
{
     ZZn2 Qx,Qy;
     Big xx,yy;

#ifdef SCOTT
     ZZn a,b,x,y,ib,w,t1,y2,ib2;
#else
     ZZn2 lambda,ox;
#endif
     Q.get(xx,yy);
     Qx=(ZZn)xx*cube;
     Qy=(ZZn)yy;

#ifndef SCOTT
// point doubling
     lambda=(3*Qx*Qx)/(Qy+Qy);
     ox=Qx;
     Qx=lambda*lambda-(Qx+Qx);
     Qy=lambda*(ox-Qx)-Qy;
#else
// explicit point subtraction
     Qx.get(a,b);
     y=yy;
     ib=(ZZn)1/b;

     t1=a*b*b;
     y2=y*y;
     ib2=ib*ib;
     w=y2+2*t1;
     x=-w*ib2;
     y=-y*(w+t1)*(ib2*ib);
     Qx.set(x); Qy.set((ZZn)0,y);

#endif

     if (fast_tate_pairing(P,Qx,Qy,order,res)) return TRUE;
     return FALSE;
}


ECn 
charToECn (char *c, int *totLen)
{
  ECn e;
  Big x,y;
  int len = 0;
  char *orig = c;
  //   format: 4 bytes length, followed by the big

  memcpy (&len, c, sizeof (int));
  c += sizeof (int);
  x = from_binary (len, c);
  c += len;
  //  cout << "Len1 " << len << " x " << x;

  memcpy (&len, c, sizeof (int));
  c += sizeof (int);
  y = from_binary (len, c);
  c += len;
  //  cout << " Len2 " << len << " y " << y << "\n";

  e.set (x, y);

  *totLen = c - orig;
  return e;
}

Big
charToBig (char *c, int *totLen)
{
  Big a;
  int len;
  char *orig = c;

  memcpy (&len, c, sizeof (int));
  c += sizeof (int);
  a = from_binary (len, c);
  c += len;

  *totLen = c - orig;
  return a;
}

int
BigTochar (Big &x, char *c, int s)
{
  int len = 0;
  int totlen = sizeof (int);

  //   format: 4 bytes length, followed by the big
  if (s <= sizeof (int))
    return -1;
  // Code assumes epoint contains either nulls or bigs > 0
  s -= sizeof (int);
  c += sizeof (int);
  if (x.iszero()) {
    len = 0;
  } else {
    len = to_binary (x, s, c, FALSE);
  }

  if (len < 0)
    return -1;
  memcpy ((char *)(c - sizeof(int)), (void *)&len, sizeof (int));
  totlen += len;
  s -= len;
  c += len;
  //  cout << "Len1 " << len << " x " << x;

  return totlen;
}

ZZn2 
charToZZn2 (char *c, int *totLen)
{
  ZZn2 z;
  int len;
  Big a,b;
  char *orig = c;

  memcpy (&len, c, sizeof (int));
  c += sizeof (int);
  a = from_binary (len, c);
  c += len;
  //  cout << "chartozzn2 a: (" << len << ") " 
  //    << a << "\n";

  memcpy (&len, c, sizeof (int));
  c += sizeof (int);
  b = from_binary (len, c);
  //  cout << "chartozzn2 b: (" << len << ") " 
  //   << b << "\n";
  c += len;

  z.set (a, b);

  *totLen = c - orig;
  return z;
}

int
ECnTochar (ECn &e, char *c, int s)
{

  Big x, y;
  e.get(x, y);
  int len = 0;
  int totlen = sizeof (int)*2;

  //  cout << "Entering ECnTochar" << endl;
  //   format: 4 bytes length, followed by the big
  if (s <= sizeof (int))
    return -1;
  // Code assumes epoint contains either nulls or bigs > 0
  s -= sizeof (int);
  c += sizeof (int);
  if (x.iszero()) {
    len = 0;
  } else {  
    len = to_binary (x, s, c, FALSE);
  }
  if (len < 0) {
    return -1;
  }

  memcpy ((char *)(c - sizeof(int)), (void *)&len, sizeof (int));

  totlen += len;
  s -= len;
  c += len;
  //    cout << "Len1 " << len << " x " << x;


  if (s <= sizeof (int))
    return -1;
  s -= sizeof (int);
  c += sizeof (int);
  len = to_binary (y, s, c, FALSE);
  if (len < 0)
    return -1;
  memcpy ((char *)(c - sizeof(int)), (void *)&len, sizeof (int));
  totlen += len;
  //  cout << "Len2 " << len << " y " << y;

  return totlen;
}

int
ZZn2Tochar (ZZn2 &z, char *c, int s)
{
  int len = 0;
  int totlen = 2*sizeof(int);
  Big a,b;
  z.get (a, b);

  s -= sizeof (int);
  c += sizeof (int);
  if (a.iszero()) {
    len = 0;
  } else {
    len = to_binary(a, s, c, FALSE);
  }
  if (len < 0)
    return -1;
  memcpy ((char *)(c - sizeof (int)), (void *)&len, sizeof (int));
  totlen += len;
  s -= len;
  c += len;


  s -= sizeof (int);
  c += sizeof (int);
  if (b.iszero()) {
    len = 0;
  } else {
    len = to_binary(b, s, c, FALSE);
  }
  if (len < 0)
    return -1;
  memcpy ((char *)(c - sizeof (int)), (void *)&len, sizeof (int));
  totlen += len;

  return totlen;
}

// entropyCollect()
//
// Fill a buffer with system entropy.  On linux this is
// implemented by reading from /dev/urandom or /dev/random
// (depending on what's in DEVRANDOM).  In principle
// we should use /dev/random, but sometimes it blocks.
//
// On other platforms this routine will fail or do bad things.

BOOL
entropyCollect(char *entropyBuf, int entropyBytes)
{
#ifdef WIN32
/*
 * this function is from libtomcrypt
 */
	int			res;
	HCRYPTPROV	h = 0;

	res = CryptAcquireContext(&h, NULL, MS_DEF_PROV, PROV_RSA_FULL,
							  (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET));
	if (!res)
		res = CryptAcquireContext(&h, NULL, MS_DEF_PROV, PROV_RSA_FULL,
			   CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET);
	if (!res)
		return dst;

	res = CryptGenRandom(h, entropyBytes, entropyBuf);
	CryptReleaseContext(h, 0);
	
	if (res == TRUE) {
		return TRUE;
	} else
		PRINT_DEBUG_STRING("Could not seed RNG from MS crypto API.");
		return FALSE;
	}
#else
  // Open /dev/random for reading
  FILE* fp = fopen(DEVRANDOM, "rb");
  if (fp == NULL) { 
    PRINT_DEBUG_STRING("Could not open /dev/random or /dev/urandom.");
    return FALSE; 
  }

  // Read entropyBytes from /dev/(u)random
  int totRead = fread(entropyBuf, sizeof(char), entropyBytes, fp);

  // Close the file
  fclose(fp);
  
  if (totRead != entropyBytes) {
    PRINT_DEBUG_STRING("Could not collect enough entropy from /dev/(u)random");
    return FALSE;
  } else {
    return TRUE;
  }
#endif
}

// bufrand()
//
// Seeds the MIRACL RNG using a buffer of seed material

void
bufrand(char* seedbuf, int seedsize)
{
  miracl *mir = &precision;
  mir->borrow = 0L;
  mir->rndptr = 0;
  mir->ira[0];
  
  if (seedsize > NK * (sizeof(mr_unsign32))) {
    seedsize = NK * sizeof(mr_unsign32);
  }

  int seedelts = seedsize / sizeof(mr_unsign32);
  mr_unsign32 *seedbufLongs = (mr_unsign32*)seedbuf;

  for (int i = 0; i < seedelts; i++) {
    mir->ira[i] = seedbufLongs[i];
  }

  // Warm up the random number generator as per irand
  for (int i=0;i<1000;i++) brand(_MIPPO_ );
}

// printDebugString()
//
// Outputs a debugging string

void
printDebugString(string debugString)
{
  if (gDebugPrint == TRUE) {
    cout << debugString << endl;
  }
}

//
// Class members (CurveParams)
//

int
CurveParams::getSerializedSize(SERIALIZE_MODE mode)
{
  switch (mode) {
  case SERIALIZE_BINARY:
    return (PBITS/8 + 10) * 9;
    break;
  case SERIALIZE_HEXASCII:
    break;
  }

  // Invalid serialization mode
  return 0;
}  

int
CurveParams::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
{
  int totSize = 0;

  // Make sure we've been given a large enough buffer
  if (buffer == NULL || maxBuffer < this->getSerializedSize(mode)) {
    return 0;
  }

  // Set base-16 ASCII encoding
  miracl *mip=&precision;
  mip->IOBASE = 16;

  switch (mode) {
  case SERIALIZE_BINARY:
    //int bits;
    //Big p, q, qsquared;
    //ECn P;  
    //ZZn2 Z;
    //ZZn2 Zprecomp;
    //ZZn2 cube;
    
    Big bbits = this->bits;
    int size = BigTochar(bbits, buffer, maxBuffer);
    if (size <= 0) return 0;
    totSize += size;
    buffer += size;
    
    size = BigTochar(this->p, buffer, maxBuffer - totSize);
    if (size <= 0) return 0;
    totSize += size;
    buffer += size;
    
    size = BigTochar(this->q, buffer, maxBuffer - totSize);
    if (size <= 0) return 0;
    totSize += size;
    buffer += size;
    
    size = ECnTochar(this->P, buffer, maxBuffer - totSize);
    if (size <= 0) return 0;
    totSize += size;
    buffer += size;
    
    size = ZZn2Tochar(this->Z, buffer, maxBuffer - totSize);
    if (size <= 0) return 0;
    totSize += size;
    buffer += size;
    
    size = ZZn2Tochar(this->cube, buffer, maxBuffer - totSize);
    if (size <= 0) return 0;
    totSize += size;
    buffer += size;
    
    return totSize;
    break;
  
    //  case SERIALIZE_HEXASCII:
    //break;
  }

  // Invalid serialization mode
  return 0;
}

BOOL
CurveParams::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
{
  // Make sure we've been given a real buffer
  if (buffer == NULL) {
    return 0;
  }

  // Set base-16 ASCII encoding
  miracl *mip=&precision;
  mip->IOBASE = 16;

  switch (mode) {
  case SERIALIZE_BINARY:
    //int bits;
    //Big p, q, qsquared;
    //ECn P;  
    //ZZn2 Z;
    //ZZn2 Zprecomp;
    //ZZn2 cube;
    
    int len;
    this->bits = toint(charToBig(buffer, &len));
    if (len <= 0) return FALSE;
    buffer += len;

    this->p = charToBig(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->q = charToBig(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->qsquared = pow(q, 2);

    this->P = charToECn(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->Z = charToZZn2(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->cube = charToZZn2(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

// Set up the elliptic curve 
#ifdef AFFINE
  ecurve(0,1,params.p,MR_AFFINE);   
#endif
#ifdef PROJECTIVE
  ecurve(0,1,this->p,MR_PROJECTIVE);
#endif

    return TRUE;
    break;


  case SERIALIZE_HEXASCII:
    // Serialize to hexadecimal in ASCII 
    // TBD
    return FALSE;
    break;
  }

  // Invalid serialization mode
  return 0;
}
