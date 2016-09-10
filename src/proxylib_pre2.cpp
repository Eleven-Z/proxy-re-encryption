// The JHU-MIT Proxy Re-encryption Library (PRL)
//
// proxylib_pre2.cpp: Contains the implementation of the 
// PRE2 proxy re-encryption scheme.
//
// ================================================================
// 	
// Copyright (c) 2007, Matthew Green, Giuseppe Ateniese, Kevin Fu,
// Susan Hohenberger.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:												
//
// Redistributions of source code must retain the above copyright 
// notice, this list of conditions and the following disclaimer.  
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in 
// the documentation and/or other materials provided with the 
// distribution.
//
// Neither the names of the Johns Hopkins University, the Massachusetts
// Institute of Technology nor the names of its contributors may be 
// used to endorse or promote products derived from this software 
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.

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
#include "proxylib_pre2.h"

#ifdef BENCHMARKING
static struct timeval gTstart, gTend;
static struct timezone gTz;
extern Benchmark gBenchmark;
#endif
extern Miracl precision;

// PRE2_generate_params()
//
// Generate global public parameters for use with the PRE2 scheme.  A single set of
// parameters is shared among all users in a PRE2 deployment.
//
// Public parameters consist of the following elements:
//		q: a QBITS-bits prime number (order of group G)
//		p: a PBITS-bits prime number (defines the field F_p)
//		cube: a cube root of unity (solution in Fp2 of x^3=1 mod p)
//		P: a generator of group G
//		Z: the value Z = e(P, P) (where e() is the Tate pairing)

BOOL 
PRE2_generate_params(CurveParams &params)
{
  // PRE2 uses the same parameters as PRE1, so we call to that routine.
  return PRE1_generate_params(params);
}

//
// Generate a public/secret keypair for the PRE2 scheme.  
// Secret keys have the form a1 \in Z*q
// Public keys have the form a1*P \in G.
//
// Where P is the public generator of G

BOOL 
PRE2_keygen(CurveParams &params, ProxyPK_PRE2 &publicKey, ProxySK_PRE2 &secretKey)
{
  // Pick random secret key a1 \in Z*q, and store in "secretKey"
  Big a1=rand(params.q);
  secretKey.set(a1);

  // Compute the value Ppub = (a1 * P) \in G
  ECn Ppub2 = (a1 * params.P);
  
  // Pre-compute the value Z^a1 \in G_T by computing:
  // Zpub = e(P, a1 * P)
  // This is for performance reasons later on--- it's not strictly
  // necessary.
  ZZn2 Zpub;
  if (ecap(params.P, Ppub2, params.q, params.cube, Zpub) == FALSE) {
    // Pairing failed.  Oops.
    PRINT_DEBUG_STRING("PRE2 key generation pairing failed."); 
    return false;
  }
     
  // Store the values Ppub2 \in G, Zpub \in G_t in "publicKey".
  // Note that the value Zpub is included only to speed up encryption
  // within the library.
  publicKey.set(Zpub, Ppub2);
  
  // Success
  return TRUE;
}

// PRE2_level1_encrypt()
//
// Takes a plaintext and a public key and generates a first-level
// (non-re-encryptable) ciphertext in the values res1 and res2.
//
// res1 = Z^{(a_1)k}
// res2 = (plaintext) * Z^k

BOOL 
PRE2_level1_encrypt(CurveParams &params, Big &plaintext, ProxyPK_PRE2 &publicKey, ProxyCiphertext_PRE2 &ciphertext)
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

// PRE2_level2_encrypt()
//
// Takes a plaintext and a public key and generates a second-level
// (re-encryptable) ciphertext in the values res1 and res2
//
// c1 = k * (a1 * P), c2 = (plaintext) * Z^k

BOOL PRE2_level2_encrypt(CurveParams &params, Big &plaintext, ProxyPK_PRE2 &publicKey, ProxyCiphertext_PRE2 &ciphertext)
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
  c1 = k * publicKey.Ppub2;

  // Compute res2 = plaintext * Zpub1^k
  zPlaintext.set(plaintext, 0);
  temp = pow(params.Z, k);
  c2 = zPlaintext * temp;
  
  // Set the ciphertext structure with (c1, c2)
  ciphertext.set(CIPH_SECOND_LEVEL, c1, c2);

#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(LEVELTWOENCTIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// PRE2_delegate()
//
// Given a delegate's public key and the original target's secret key,
// produce a delegation key that can be used to re-encrypt second
// level ciphertexts.
//
// reskey = inverse(delegator.a1) * (delegatee.b2 * P)
//
// A security note: It may be possible for an adversary to use the key 
// delegation process as an oracle for decryption.  It is recommended that
// delegators verify the correctness of any delegatee public key
// by e.g., requiring the delegatee to "prove knowledge" of the secret key.

BOOL PRE2_delegate(CurveParams &params, ProxyPK_PRE2 &delegatee,
		   ProxySK_PRE2 &delegator, DelegationKey_PRE2 &reskey)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif
 
  // Compute reskey = delegator.a1 * delegatee.Ppub2
  Big a1inv = inverse(delegator.a1, params.q);
  reskey = a1inv * (delegatee.Ppub2);

  ECn Q = delegator.a1 * params.P;
 
  ZZn2 res1;
  
#ifdef BENCHMARKING
  gettimeofday(&gTend, &gTz);
  gBenchmark.CollectTiming(DELEGATETIMING, CalculateUsecs(gTstart, gTend));
#endif

  return true;
}

// PRE2_reencrypt()
//
// Given a "second-level" ciphertext (c1, c2), along with a 
// delegation key, produces a re-encrypted ciphertext.
//
// c1 = e(k*a1*P, b1*inv(a1)*P) = Z^{k*b1}
// c2 = c2

BOOL 
PRE2_reencrypt(CurveParams &params, ProxyCiphertext_PRE2 &origCiphertext, 
	       DelegationKey_PRE2 &delegationKey, 
	       ProxyCiphertext_PRE2 &newCiphertext)
{
#ifdef BENCHMARKING
  gettimeofday(&gTstart, &gTz);
#endif

  SAFESTATIC ZZn2 res1;

  // Compute the pairing res1 = e(k*a1*P, delegation)
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

// PRE2_decrypt()
//
// Decrypt a ciphertext and return the plaintext.  This routine handles
// three different types of ciphertext.
//
// 1. If this is a first-level ciphertext it will have the form:
//    c1 = Z^{(a1)k}, c2 = plaintext * Z^k
// 2. If this is a re-encrypted ciphertext, it will have the form:
//    c1 = Z^{(b1)k}, c2 = plaintext * Z^k
// 3. If this is a second-level ciphertext, it will have the form:
//	  c1 = k*a1*P, c2 = plaintext * Z^k
//
// To decrypt case 1: plaintext = c2 / c1^inv(a1)
// To decrypt case 2: plaintext = c2 / c1^inv(a2)
// To decrypt case 3: plaintext = c2 / e(c1, (delegation = a1 * P))

BOOL PRE2_decrypt(CurveParams &params, ProxyCiphertext_PRE2 &ciphertext, ProxySK_PRE2 &secretKey, Big &plaintext)
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
 case CIPH_REENCRYPTED:
   // temp = c1^inv(a1)
   temp = pow(ciphertext.c1b, inverse(secretKey.a1, params.qsquared));
   //cout << "decrypt: temp = " << temp << endl;
   break;
 case CIPH_SECOND_LEVEL:
   // temp = e(c1, a1 * P)
   del = inverse(secretKey.a1, params.q) * params.P;
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
SerializeDelegationKey_PRE2(DelegationKey_PRE2 &delKey, SERIALIZE_MODE mode, char *buffer, int maxBuffer)
{
  DelegationKey_PRE1* dk = (DelegationKey_PRE1*)&delKey;
  return SerializeDelegationKey_PRE1(*dk, mode, buffer, maxBuffer);
}

// DeserializeDelegationKey_PRE1()
//
// Deserialize a delegation key from a buffer

BOOL
DeserializeDelegationKey_PRE2(DelegationKey_PRE1 &delKey, SERIALIZE_MODE mode, char *buffer, int bufSize)
{
  DelegationKey_PRE1* dk = (DelegationKey_PRE1*)&delKey;
  return DeserializeDelegationKey_PRE1(*dk, mode, buffer, bufSize);
}

//
// Class members (ProxyPK_PRE2)
//
#if 0
int
ProxyPK_PRE2::getSerializedSize(SERIALIZE_MODE mode)
{
  return ProxyPK_PRE1::getSerializedSize(mode);
}  

int
ProxyPK_PRE2::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
{
  return ProxyPK_PRE1::serialize(mode, buffer, maxBuffer);
}

BOOL
ProxyPK_PRE2::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
{
  return ProxyPK_PRE1::serialize(mode, buffer, bufSize);
}

#endif
#if 0
//
// Class members (ProxySK_PRE2)
//

int
ProxySK_PRE2::getSerializedSize(SERIALIZE_MODE mode)
{
  switch (mode) {
  case SERIALIZE_BINARY:
    return (QBITS/8 + 10);
    break;
  case SERIALIZE_HEXASCII:
    break;
  }

  // Invalid serialization mode
  return 0;
}  

int
ProxySK_PRE2::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
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
    int len = BigTochar (this->a1, buffer, maxBuffer);
    if (len <= 0) return 0;
    buffer += len;
    totSize += len;

    //cout << "a1: " << this->a1 << endl;
    //cout << "a2: " << this->a2 << endl;

    return totSize;

    break;

  case SERIALIZE_HEXASCII:

    string temp;
    buffer << this->a1;
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
ProxySK_PRE2::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
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
#endif

#if 0
//
// Class members (ProxyCiphertext_PRE2)
//

int
ProxyCiphertext_PRE2::getSerializedSize(SERIALIZE_MODE mode)
{
  return ProxyCiphertext_PRE1::getSerializedSize(mode);
}  

int
ProxyCiphertext_PRE2::serialize(SERIALIZE_MODE mode, char *buffer, int maxBuffer)
{
  return ProxyCiphertext_PRE1::serialize(mode, buffer, maxBuffer);
}

BOOL
ProxyCiphertext_PRE2::deserialize(SERIALIZE_MODE mode, char *buffer, int bufSize)
{
  return ProxyCiphertext_PRE1::deserialize(mode, buffer, bufSize);
}
#endif




