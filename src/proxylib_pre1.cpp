// The JHU-MIT Proxy Re-encryption Library (PRL)
//
// proxylib_pre1.cpp: Contains the  implementation of the 
// PRE1 proxy re-encryption scheme.
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
#include <sys/time.h>

using namespace std;

#ifdef BENCHMARKING
	#include "benchmark.h"
#endif
#include "proxylib_api.h"
#include "proxylib.h"
#include "proxylib_pre1.h"

#ifdef BENCHMARKING
static struct timeval gTstart, gTend;
static struct timezone gTz;
extern Benchmark gBenchmark;
#endif
extern Miracl precision;

// PRE1_generate_params()
//
// Generate global public parameters for use with the PRE1 scheme.  A single set of
// parameters is shared among all users in a PRE1 deployment.
//
// Public parameters consist of the following elements:
//		q: a QBITS-bits prime number (order of group G)
//		p: a PBITS-bits prime number (defines the field F_p)
//		cube: a cube root of unity (solution in Fp2 of x^3=1 mod p)
//		P: a generator of group G
//		Z: the value Z = e(P, P) (where e() is the Tate pairing)

BOOL 
PRE1_generate_params(CurveParams &params)
{
  miracl *mip=&precision;

  mip->IOBASE = 10;
  // Generate a q value.  This can be fixed or random, depending on the
  // SIMPLE pre-compiler directive.  If SIMPLE, we use the fixed value
  // 2^159 + 2^17 + 1.  Otherwise we select a random QBITS-bits prime.
  
#ifdef SIMPLE
  // Fixed q
  params.q= pow((Big)2,159) + pow((Big)2,17) + 1;
#else
  // Random q 
  
  forever {
    Big n=rand(QBITS-1,2);  // 159 bit number, base 2 
    params.q=2*n+1;            // 160 bit
    while (!prime(params.q)) params.q+=2;
    if (bits(params.q)>QBITS) continue;
    break;
  }
#endif
  
  params.qsquared = pow((Big)params.q, 2);
  //  cout << "q = " << params.q << ", q^2 = " << params.qsquared << endl;

  // Generate a p value.  This is a random PBITS-bits prime. 
  Big t=(pow((Big)2,PBITS)-1)/(2*params.q);
  Big s=(pow((Big)2,PBITS-1)-1)/(2*params.q);
  Big n;
  forever 
    {
      n=rand(t);
      if (n<s) continue;
      params.p = 2 * n * params.q - 1;
      if (params.p % 24 != 11) continue;  // must be 2 mod 3, also 3 mod 4
      if (prime(params.p)) break;
    }
  
  // Set up the elliptic curve 
#ifdef AFFINE
  ecurve(0,1,params.p,MR_AFFINE);   
#endif
#ifdef PROJECTIVE
  ecurve(0,1,params.p,MR_PROJECTIVE);
#endif

  //cout << "p: " << params.p << endl;

  // Find suitable cube root of unity (solution in Fp2 of x^3=1 mod p)  
  forever {
    //    cube=pow(randn2(),(p+1)*(p-1)/3);
    params.cube = pow(randn2(), (params.p + 1)/3);
    params.cube = pow(params.cube, params.p - 1);
    if (!params.cube.isunity()) break;
  }
  
  // Check to see that the value is actually correct.
  if (!(params.cube * params.cube * params.cube).isunity()) {
    PRINT_DEBUG_STRING("Setup failed.  Unable to find a cube root of unity.");
    return FALSE;
  }
  
  // Choose an arbitrary generator point P
  Big cof=2*n;
  forever {
    while (!params.P.set(randn())) ;
    params.P *= cof;
    if (!params.P.iszero()) break;
  }

  //cout << "P: " << params.P << endl;

  // Compute an optional EBrick class for pairing pre-computation
#if 0
  Big xx, yy;
  params.P.get(xx, yy);
  EBrick B(xx, yy,(Big)0,(Big)1,params.p,8,QBITS); 
#endif

  //cout << "Cube root of unity: " << params.cube << endl;

  //
  // Precompute the value Z = e(P, P) using the Tate pairing.  We could do this
  // at any point down the road, but it's more efficient to do it now.
  //    
  if (ecap(params.P, params.P, params.q, params.cube, params.Z) == FALSE) {
    PRINT_DEBUG_STRING("Parameter generation failed.  Unable to compute Z.");
    return FALSE;
  }
  
  // Success
  return TRUE;
}

// PRE1_keygen()
//
// Generate a public/secret keypair for the PRE1 scheme.  
// Secret keys have the form (a1, a2) \in Z*q x Z*q.
// Public keys have the form (Z^a1, a2*P) \in G_T x G.
//
// Where P is the public generator of G, and Z = e(P, P).

BOOL 
PRE1_keygen(CurveParams &params, ProxyPK_PRE1 &publicKey, ProxySK_PRE1 &secretKey)
{
  // Pick random secret key (a1, a2) \in Z*q x Z*q, and store in "secretKey"
  Big a1=rand(params.q);
  Big a2=rand(params.q);
  secretKey.set(a1, a2);

  // Compute the value Z^a1 \in G_T by computing:
  // Zpub1 = e(P, a1 * P)
  ECn temp = (a1 * params.P);
  ZZn2 Zpub1;
  if (ecap(params.P, temp, params.q, params.cube, Zpub1) == FALSE) {
    PRINT_DEBUG_STRING("Key generation failed due to pairing operation.");
    return FALSE;
  }
  
  // Compute the value Ppub2 = (a2 * P) \in G
  ECn Ppub2 = (a2 * params.P);
  
  // Store the values (Zpub1, Ppub2) \in G_T x G in "publicKey"
  publicKey.set(Zpub1, Ppub2);
  
  // Success
  return TRUE;
}

// PRE1_level1_encrypt()
//
// Takes a plaintext and a public key and generates a first-level
// (non-re-encryptable) ciphertext in the values res1 and res2.
//
// res1 = Z^{(a_i)k}
// res2 = (plaintext) * Z^k

BOOL 
PRE1_level1_encrypt(CurveParams &params, Big &plaintext, ProxyPK_PRE1 &publicKey, ProxyCiphertext_PRE1 &ciphertext)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif

  SAFESTATIC Big k;
  SAFESTATIC ZZn2 temp, c1, c2;
  SAFESTATIC ZZn2 zPlaintext;

  // Select a random value k \in Z*q, and compute res1 = Zpub1^k
  k = rand(params.q);
  c1 = pow(publicKey.Zpub1, k);
  
  // Compute res2 = plaintext * Z^k
  temp = pow(params.Z, k);
  //cout << "encrypt: params.Z = " << params.Z << endl;
  //cout << "encrypt: temp = " << temp << endl;
  zPlaintext.set(plaintext, 0);
  //cout << "encrypt: plaintext = " << zPlaintext << endl;
  c2 = zPlaintext * temp;
  //cout << "encrypt: c1 = " << c1 << endl;
  //cout << "encrypt: c2 = " << c2 << endl;

  // Set the ciphertext data structure with (c1, c2)
  ciphertext.set(CIPH_FIRST_LEVEL, c1, c2);

#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(LEVELONEENCTIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// PRE1_level2_encrypt()
//
// Takes a plaintext and a public key and generates a second-level
// (re-encryptable) ciphertext in the values res1 and res2
//
// res1 = kP, res2 = (plaintext) * Z^{(a1)k}

BOOL PRE1_level2_encrypt(CurveParams &params, Big &plaintext, ProxyPK_PRE1 &publicKey, ProxyCiphertext_PRE1 &ciphertext)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif

  SAFESTATIC Big k;
  SAFESTATIC ECn c1;
  SAFESTATIC ZZn2 temp, c2;
  SAFESTATIC ZZn2 zPlaintext;
  
  // Select a random value k \in Z*q and compute res1 = (k * P)  
  k = rand(params.q);
  c1 = k * params.P;

  // Compute res2 = plaintext * Zpub1^k
  zPlaintext.set(plaintext, 0);
  temp = pow(publicKey.Zpub1, k);
  c2 = zPlaintext * temp;
  
  // Set the ciphertext structure with (c1, c2)
  ciphertext.set(CIPH_SECOND_LEVEL, c1, c2);

#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(LEVELTWOENCTIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// PRE1_delegate()
//
// Given a delegate's public key and the original target's secret key,
// produce a delegation key that can be used to re-encrypt second
// level ciphertexts.
//
// reskey = delegator.a1 * (delegatee.b2 * P)
//
// A security note: It may be possible for an adversary to use the key 
// delegation process as an oracle for decryption.  It is recommended that
// delegators verify the correctness of any delegatee public key
// by e.g., requiring the delegatee to "prove knowledge" of the secret key.

BOOL PRE1_delegate(CurveParams &params, ProxyPK_PRE1 &delegatee, ProxySK_PRE1 &delegator, DelegationKey_PRE1 &reskey)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif
 
  // Compute reskey = delegator.a1 * delegatee.Ppub2
  reskey = delegator.a1 * (delegatee.Ppub2);

#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(DELEGATETIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// PRE1_reencrypt()
//
// Given a "second-level" ciphertext (c1, c2), along with a 
// delegation key, produces a re-encrypted ciphertext.
//
// res1 = e(kP, s1*s2*P) = Z^{k(s1)(s2)}
// res2 = c2

BOOL 
PRE1_reencrypt(CurveParams &params, ProxyCiphertext_PRE1 &origCiphertext, 
	       DelegationKey_PRE1 &delegationKey, 
	       ProxyCiphertext_PRE1 &newCiphertext)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif

  SAFESTATIC ZZn2 res1;

  // Compute the pairing res1 = e(kP, delegation)
  if (ecap(origCiphertext.c1a, delegationKey, params.q, params.cube, res1) == FALSE) {
    // Pairing failed.  Oops.
    PRINT_DEBUG_STRING("Re-encryption pairing failed."); 
    return false;
  }

  // Set the result ciphertext to (res1, c2)
  newCiphertext.set(CIPH_REENCRYPTED, res1, origCiphertext.c2);
  
#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(REENCTIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// PRE1_decrypt()
//
// Decrypt a ciphertext and return the plaintext.  This routine handles
// three different types of ciphertext.
//
// 1. If this is a first-level ciphertext it will have the form:
//    c1 = Z^{(a1)k}, c2 = plaintext * Z^k
// 2. If this is a re-encrypted ciphertext, it will have the form:
//    c1 = Z^{k(a1)(a2)}, c2 = plaintext * Z^{(a1)k}
// 3. If this is a second-level ciphertext, it will have the form:
//	  c1 = kP, c2 = plaintext * Z^{(a1)k}
//
// To decrypt case 1: plaintext = c2 / c1^inv(a1)
// To decrypt case 2: plaintext = c2 / c1^inv(a2)
// To decrypt case 3: plaintext = c2 / e(c1, (delegation = a1 * P))

BOOL PRE1_decrypt(CurveParams &params, ProxyCiphertext_PRE1 &ciphertext, ProxySK_PRE1 &secretKey, Big &plaintext)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif

  SAFESTATIC ECn del;
  SAFESTATIC ZZn2 temp;
  SAFESTATIC ZZn2 result;

 // Handle each type of ciphertext
 switch(ciphertext.type) {
 case CIPH_FIRST_LEVEL:
   // temp = c1^inv(a1)
   temp = pow(ciphertext.c1b, inverse(secretKey.a1, params.qsquared));
   //cout << "decrypt: temp = " << temp << endl;
   break;
 case CIPH_REENCRYPTED:
   // temp = c1^inv(a2)
   temp = pow(ciphertext.c1b, inverse(secretKey.a2, params.qsquared));
   break;
 case CIPH_SECOND_LEVEL:
   // temp = e(c1, a1 * P)
   del = secretKey.a1 * params.P;
   if (ecap(ciphertext.c1a, del, params.q, params.cube, temp) == FALSE) {
     PRINT_DEBUG_STRING("Decryption pairing failed.");
     return FALSE;
   }
   break;
 default:
   PRINT_DEBUG_STRING("Decryption failed: invalid ciphertext type.");
   break;
 }
 
 // Compute plaintext = c2 / temp
 result = ciphertext.c2 / temp;
 result.get(plaintext);

#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(LEVELONEDECTIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// SerializeDelegationKey_PRE1()
//
// Serialize a delegation key into a buffer

int
SerializeDelegationKey_PRE1(DelegationKey_PRE1 &delKey, SERIALIZE_MODE mode, char *buffer, int maxBuffer)
{
  int totSize = 0;

  // Set base-16 ASCII encoding
  miracl *mip=&precision;
  mip->IOBASE = 16;

  switch (mode) {
  case SERIALIZE_BINARY:
  { // Added by Jet, Sep 06, 2016
	  int len = ECnTochar (delKey, buffer, maxBuffer);
	  if (len <= 0) return 0;
	  return len;
	  break;
  }
  case SERIALIZE_HEXASCII:
  {
	  //string temp;
	  //buffer << delKey;
	  //temp.append(buffer);
	  //temp.append(ASCII_SEPARATOR);

	  //strcpy(buffer, temp.c_str());
	  //return strlen(buffer);
	  return 0;
	  break;
  }
  }

  // Invalid serialization mode
  return 0;
}

// DeserializeDelegationKey_PRE1()
//
// Deserialize a delegation key from a buffer

BOOL
DeserializeDelegationKey_PRE1(DelegationKey_PRE1 &delKey, SERIALIZE_MODE mode, char *buffer, int bufSize)
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
    int len;

    //cout << "got one " << len << endl;
    delKey = charToECn(buffer, &len);
    if (len <= 0) return FALSE;
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

//
// Class members (ProxyPK_PRE1)
//

int
ProxyPK_PRE1::getSerializedSize(SERIALIZE_MODE mode)
{
  switch (mode) {
  case SERIALIZE_BINARY:
    return (PBITS/8 + 10) * 4;
    break;
  case SERIALIZE_HEXASCII:
    break;
  }

  // Invalid serialization mode
  return 0;
}  

int
ProxyPK_PRE1::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
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
  {
	  int size = ZZn2Tochar(this->Zpub1, buffer, maxBuffer);
	  if (size <= 0) return 0;
	  totSize += size;
	  buffer += size;
	  //cout << "Zpub1: " << this->Zpub1 << endl;
	  //cout << "Ppub2: " << this->Ppub2 << endl;
	  //cout << "zzn size: " << size << endl;

	  size = ECnTochar(this->Ppub2, buffer, maxBuffer - totSize);
	  if (size <= 0) return 0;
	  totSize += size;
	  buffer += size;

	  return totSize;
	  break;
  }

  case SERIALIZE_HEXASCII:
    // Serialize to hexadecimal in ASCII 
  {
	  Big x, y;
	  string temp;
	  this->Zpub1.get(x, y);
	  buffer << x;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);
	  buffer << y;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);

	  this->Ppub2.get(x, y);
	  buffer << x;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);
	  buffer << y;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);

	  strcpy(buffer, temp.c_str());
	  return strlen(buffer);
	  break;
  }
  }

  // Invalid serialization mode
  return 0;
}

BOOL
ProxyPK_PRE1::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
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
    int len;
    this->Zpub1 = charToZZn2(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;
    //cout << "got one " << len << endl;

    this->Ppub2 = charToECn(buffer, &len);
    if (len <= 0) return FALSE;
    //cout << "Zpub1: " << this->Zpub1 << endl;
    //cout << "Ppub2: " << this->Ppub2 << endl;
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

//
// Class members (ProxySK_PRE1)
//

int
ProxySK_PRE1::getSerializedSize(SERIALIZE_MODE mode)
{
  switch (mode) {
  case SERIALIZE_BINARY:
    return (QBITS/8 + 10) * 2;
    break;
  case SERIALIZE_HEXASCII:
    break;
  }

  // Invalid serialization mode
  return 0;
}  

int
ProxySK_PRE1::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
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
  {
	  int len = BigTochar (this->a1, buffer, maxBuffer);
    if (len <= 0) return 0;
    buffer += len;
    totSize += len;

    len = BigTochar (this->a2, buffer, maxBuffer);
    if (len <= 0) return 0;
    buffer += len;
    totSize += len;

    //cout << "a1: " << this->a1 << endl;
    //cout << "a2: " << this->a2 << endl;

    return totSize;

    break;
  }

  case SERIALIZE_HEXASCII:

    string temp;
    buffer << this->a1;
    temp.append(buffer);
    temp.append(ASCII_SEPARATOR);
    buffer << this->a2;
    temp.append(buffer);
    temp.append(ASCII_SEPARATOR);

    strcpy(buffer, temp.c_str());
    return strlen(buffer);
    break;
  }

  // Invalid serialization mode
  return 0;
}

BOOL
ProxySK_PRE1::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
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
    int len;

    //cout << "got one " << len << endl;
    this->a1 = charToBig(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->a2 = charToBig(buffer, &len);
    if (len <= 0) return FALSE;
    //cout << "a1: " << this->a1 << endl;
    //cout << "a2: " << this->a2 << endl;
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

//
// Class members (ProxyCiphertext_PRE1)
//

int
ProxyCiphertext_PRE1::getSerializedSize(SERIALIZE_MODE mode)
{
  switch (mode) {
  case SERIALIZE_BINARY:
    return (PBITS/8 + 10) * 3;
    break;
  case SERIALIZE_HEXASCII:
    break;
  }

  // Invalid serialization mode
  return 0;
}  

int
ProxyCiphertext_PRE1::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
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
  {
	  *buffer = (char)this->type;
	  buffer++;
	  totSize++;

	  int len = ECnTochar (this->c1a, buffer, maxBuffer - totSize);
	  if (len <= 0) return 0;
	  buffer += len;
	  totSize += len;

	  len = ZZn2Tochar (this->c1b, buffer, maxBuffer - totSize);
	  if (len <= 0) return 0;
	  buffer += len;
	  totSize += len;

	  len = ZZn2Tochar (this->c2, buffer, maxBuffer - totSize);
	  if (len <= 0) return 0;
	  buffer += len;
	  totSize += len;

	  return totSize;

    break;
  }

  case SERIALIZE_HEXASCII:
  {
#if 0
	  string temp;
	  buffer << this->c1a;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);
	  buffer << this->c1b;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);
	  buffer << this->c2;
	  temp.append(buffer);
	  temp.append(ASCII_SEPARATOR);

	  strcpy(buffer, temp.c_str());
	  return strlen(buffer);
#endif

	  return 0;
	  break;
  }
  }

  // Invalid serialization mode
  return 0;
}

BOOL
ProxyCiphertext_PRE1::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
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
    int len;
    this->type = (CIPHERTEXT_TYPE)(*buffer);
    buffer++;

    //cout << "got one " << len << endl;
    this->c1a = charToECn(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->c1b = charToZZn2(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    this->c2 = charToZZn2(buffer, &len);
    if (len <= 0) return FALSE;
    buffer += len;

    //cout << "a1: " << this->a1 << endl;
    //cout << "a2: " << this->a2 << endl;
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

