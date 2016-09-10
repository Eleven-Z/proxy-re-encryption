// The JHU-MIT Proxy Re-encryption Library (PRL)
//
// proxylib_api.c: C language wrapper.
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
#include "proxylib_pre2.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/time.h>

//
// proxylib_initLibrary()
//

int
proxylib_initLibrary(char *seedbuf, int bufsize)
{
  // Initialize the library
  if (initLibrary((seedbuf == NULL), seedbuf, bufsize) == FALSE) {
    return ERROR_OTHER;
  }

  return ERROR_NONE;
}

// proxylib_generateParams()
//
// Allocates memory and generates a set of public parameters 
// for use with the library.

int
proxylib_generateParams(void **params, SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;

  CurveParams *curveParams = new CurveParams();
  switch(schemeID) {
  case SCHEME_PRE1:
    if (PRE1_generate_params(*curveParams) == TRUE) {
      error = ERROR_NONE;
    }
    break;
  case SCHEME_PRE2:
    if (PRE2_generate_params(*curveParams) == TRUE) {
      error = ERROR_NONE;
    }
    break;
  }

  *params = (void*)curveParams;
  return error;
}

// proxylib_serializeParams()
//
// Serializes a set of parameters into a buffer.

int
proxylib_serializeParams(void *params, char *buffer, int *bufferSize, int bufferAvailSize,
		SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  int serialSize = 0;
  
  CurveParams *cp = (CurveParams*)params;
  switch(schemeID) {
  case SCHEME_PRE1:
    if (cp.getSerializedSize(SERIALIZE_BINARY) <= bufferAvailSize) {
		*bufferSize = cp.serialize(SERIALIZE_BINARY, buffer, bufferAvailSize);
		if (*bufferSize > 0) { error = ERROR_NONE; }
	}
    break;
  case SCHEME_PRE2:
    if (cp.getSerializedSize(SERIALIZE_BINARY) <= bufferAvailSize) {
		*bufferSize = cp.serialize(SERIALIZE_BINARY, buffer, bufferAvailSize);
		if (*bufferSize > 0) { error = ERROR_NONE; }
	}
    break;
  }

  return error;
}

// proxylib_deserializeParams()
//
// Deserializes a buffer of parameters and returns a newly-allocated buffer.

int
proxylib_deserializeParams(char *buffer, int bufferSize, void **params,
		SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  
  CurveParams *cp = new CurveParams;
  if (cp.deserialize(SERIALIZE_BINARY, buffer, bufferSize) == FALSE) {
	delete cp;
	*params = NULL;
  } else {
	error = ERROR_NONE;
	*params = cp;
  }
  
  return error;
}

// proxylib_destroyParams()
//
// Deallocates a set of parameters created using
// proxylib_generateParams().

int
proxylib_destroyParams(void *params)
{
  if (params != NULL) {
    CurveParams *cp = (CurveParams*)params;
    free(cp);
  }

  return ERROR_NONE;
}

// proxylib_generateKeys()
//
// Generate a public/private keypair.  Allocates memory.

int
proxylib_generateKeys(void *params, void **pk, void **sk, 
		      SCHEME_TYPE schemeID)
{
  CurveParams *cp = (CurveParams*)params;
  int error = ERROR_OTHER;

  switch(schemeID) {
  case SCHEME_PRE1:
    {
      ProxyPK_PRE1 *pubKey = new ProxyPK_PRE1();
      ProxySK_PRE1 *secKey = new ProxySK_PRE1();
      if (PRE1_keygen(*cp, *pubKey, *secKey) == TRUE) {
	error = ERROR_NONE;
      }
      *pk = (void*)pubKey;
      *sk = (void*)secKey;
    }
    break;
  case SCHEME_PRE2:
    {
      ProxyPK_PRE2 *pubKey = new ProxyPK_PRE2();
      ProxySK_PRE2 *secKey = new ProxySK_PRE2();
      if (PRE2_keygen(*cp, *pubKey, *secKey) == TRUE) {
	error = ERROR_NONE;
      }
      *pk = (void*)pubKey;
      *sk = (void*)secKey;
    }
    break;
  }

  return error;
}

// proxylib_serializeKeys()
//
// Serializes a pair of keys into a buffer.

int
proxylib_serializeKeys(void *params, void *pk, void *sk, char *pkBuf, char *skBuf,
	int *pkBufSize, int *skBufSize, int bufferAvailSize, SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  
  CurveParams *cp = (CurveParams*)params;
  switch(schemeID) {
  case SCHEME_PRE1:
	PublicKey_PRE1 *pubkey = (PublicKey_PRE1*)pk;
	*pkBufSize = pubkey.serialize(SERIALIZE_BINARY, pkBuf, bufferAvailSize);
	if (*pkBufSize > 0) { error = ERROR_NONE; }
	
	SecretKey_PRE1 *seckey = (SecretKey_PRE1*)sk;
	*skBufSize = seckey.serialize(SERIALIZE_BINARY, skBuf, bufferAvailSize);
	if (*skBufSize > 0) { error = ERROR_NONE; }
    break;
  case SCHEME_PRE2:
	PublicKey_PRE2 *pubkey = (PublicKey_PRE2*)pk;
	*pkBufSize = pubkey.serialize(SERIALIZE_BINARY, pkBuf, bufferAvailSize);
	if (*pkBufSize > 0) { error = ERROR_NONE; }
	
	SecretKey_PRE2 *seckey = (SecretKey_PRE2*)sk;
	*skBufSize = seckey.serialize(SERIALIZE_BINARY, skBuf, bufferAvailSize);
	if (*skBufSize > 0) { error = ERROR_NONE; }
    break;
  }

  return error;
}

// proxylib_serializeKeys()
//
// Serializes a pair of keys into a buffer.

int
proxylib_deserializeKeys(void *params, char *pkBuf, char *skBuf,
	int pkBufSize, int skBufSize, void **pk, void **sk, SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  
  CurveParams *cp = (CurveParams*)params;
  switch(schemeID) {
  case SCHEME_PRE1:
	PublicKey_PRE1 *pubkey = new PublicKey_PRE1;
	if (pubkey.deserialize(SERIALIZE_BINARY, pkBuf, pkBufSize) == TRUE) {
	  error = ERROR_NONE;
	}
	*pk = (void*)pubkey;
		
	SecretKey_PRE1 *seckey = new SecretKey_PRE1;
	if (seckey.deserialize(SERIALIZE_BINARY, skBuf, skBufSize) == TRUE) {
	  error = ERROR_NONE;
	}
	*sk = (void*)seckey;
    break;
  case SCHEME_PRE2:
	PublicKey_PRE2 *pubkey = new PublicKey_PRE2;
	if (pubkey.deserialize(SERIALIZE_BINARY, pkBuf, pkBufSize) == TRUE) {
	  error = ERROR_NONE;
	}
	*pk = (void*)pubkey;
		
	SecretKey_PRE2 *seckey = new SecretKey_PRE2;
	if (seckey.deserialize(SERIALIZE_BINARY, skBuf, skBufSize) == TRUE) {
	  error = ERROR_NONE;
	}
	*sk = (void*)seckey;
    break;
  }

  return error;
}

// proxylib_destroyKeys()
//
// Destroy a public or secret key.

int
proxylib_destroyKeys(void *pk, void *sk, SCHEME_TYPE schemeID)
{
  int error = ERROR_NONE;
  
  switch(schemeID) {
  case SCHEME_PRE1:
    {  
		if (pk != NULL) {
			ProxyPK_PRE1 *pubkey = (ProxyPK_PRE1*)pk;
			delete pubkey;
		}
		
		if (sk != NULL) {
			ProxySK_PRE1 *seckey = (ProxySK_PRE1*)sk;
			delete seckey;
		}
	}
	break;

  case SCHEME_PRE2:
    {  
		if (pk != NULL) {
			ProxyPK_PRE2 *pubkey = (ProxyPK_PRE2*)pk;
			delete pubkey;
		}
		
		if (sk != NULL) {
			ProxySK_PRE2 *seckey = (ProxySK_PRE2*)sk;
			delete seckey;
		}
	}
	break;
  }
  
  return error;
}

// proxylib_encrypt()
//
// Encrypt a message using a public key.
//
// Returns: ERROR_NONE, ERROR_OTHER, ERROR_PLAINTEXT_TOO_LONG

int
proxylib_encrypt(void *params, void *pk, char *message, int messageLen, 
		 char *ciphertext, int *ciphLen, CIPHERTEXT_TYPE ctype,
		 SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  CurveParams *cp = (CurveParams *)params;
  Big msg;

  if (encodePlaintextAsBig(*cp, message, messageLen, msg) == FALSE) {
    error = ERROR_PLAINTEXT_TOO_LONG;
    return error;
  }

  switch(schemeID) {
  case SCHEME_PRE1:
    {
      ProxyPK_PRE1 *pubkey = (ProxyPK_PRE1 *)pk;
      ProxyCiphertext_PRE1 ctext;
      
      switch(ctype) {
      case CIPH_FIRST_LEVEL:
	if (PRE1_level1_encrypt(*cp, msg, *pubkey, ctext) == FALSE) {
	  return ERROR_OTHER;
	}
	break;
      case CIPH_SECOND_LEVEL:
	if (PRE1_level2_encrypt(*cp, msg, *pubkey, ctext) == FALSE) {
	  return ERROR_OTHER;
	}
	break;
      default:
	return ERROR_OTHER;
      }

      *ciphLen = ctext.serialize(SERIALIZE_BINARY, ciphertext, *ciphLen);
      if (*ciphLen > 0) {
	error = ERROR_NONE;
      } 
    }
    break;
  case SCHEME_PRE2: 
    {
      ProxyPK_PRE2 *pubkey = (ProxyPK_PRE2 *)pk;
      ProxyCiphertext_PRE2 ctext;
      switch(ctype) {
      case CIPH_FIRST_LEVEL:
	if (PRE2_level1_encrypt(*cp, msg, *pubkey, ctext) == FALSE) {
	  return ERROR_OTHER;
	}
	break;
      case CIPH_SECOND_LEVEL:
	if (PRE2_level2_encrypt(*cp, msg, *pubkey, ctext) == FALSE) {
	  return ERROR_OTHER;
	}
	break;
      default:
	return ERROR_OTHER;
      }

      *ciphLen = ctext.serialize(SERIALIZE_BINARY, ciphertext, *ciphLen);
      if (*ciphLen > 0) {
	error = ERROR_NONE;
      }
    }
    break;
  }

  return error;
}

// proxylib_decrypt()
//
// Decrypt a message using a secret key.  Places the result into
// message, and returns the length in messageLen.
//
// Returns: ERROR_NONE, ERROR_OTHER, ERROR_PLAINTEXT_TOO_LONG

int
proxylib_decrypt(void *params, void *sk, char *message, int *messageLen, 
		 char *ciphertext, int ciphLen, 
		 SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  CurveParams *cp = (CurveParams *)params;
  Big msg;

  switch(schemeID) {
  case SCHEME_PRE1:
    {
      // Deserialize the ciphertext
      ProxyCiphertext_PRE1 ctext;
      if (ctext.deserialize(SERIALIZE_BINARY, ciphertext, ciphLen) ==
	  FALSE) {
	return ERROR_OTHER;
      }

      ProxySK_PRE1 *seckey = (ProxySK_PRE1 *)sk;
      if (PRE1_decrypt(*cp, ctext, *seckey, msg) == FALSE) {
	return ERROR_OTHER;
      }
    }
    break;
  case SCHEME_PRE2: 
    {
      // Deserialize the ciphertext
      ProxyCiphertext_PRE2 ctext;
      if (ctext.deserialize(SERIALIZE_BINARY, ciphertext, ciphLen) ==
	  FALSE) {
	return ERROR_OTHER;
      }

      ProxySK_PRE2 *seckey = (ProxySK_PRE2 *)sk;
      if (PRE2_decrypt(*cp, ctext, *seckey, msg) == FALSE) {
	return ERROR_OTHER;
      }
    }    
    break;
  default:
    return ERROR_OTHER;
  }

  // Decode the result as a binary buffer
  if (decodePlaintextFromBig(*
cp, message, *messageLen, messageLen, msg) == 
      FALSE) {
    return ERROR_OTHER;
  }

  return error;
}

// proxylib_generateDelegationKey()
//
// Generate a public/private keypair.  Allocates memory.

int
proxylib_generateDelegationKey(void *params, void *sk1, void *pk2, void** delKey, 
		      SCHEME_TYPE schemeID)
{
  CurveParams *cp = (CurveParams*)params;
  int error = ERROR_OTHER;

  switch(schemeID) {
  case SCHEME_PRE1:
    {
      ProxyPK_PRE1 *pubKey = (ProxyPK_PRE1 *)pk2;
      ProxySK_PRE1 *secKey = (ProxySK_PRE1 *)sk1;
	  DelegationKey_PRE1 *delegationKey = new DelegationKey_PRE1;
	  
	  if (PRE1_delegate(*cp, *pk2, *sk1, *delegationKey) == FALSE) {
	    error = ERROR_NONE;
      }
	  *delKey = (void*)delegationKey;
    }
    break;
  case SCHEME_PRE1:
    {
      ProxyPK_PRE2 *pubKey = (ProxyPK_PRE1 *)pk2;
      ProxySK_PRE2 *secKey = (ProxySK_PRE1 *)sk1;
	  DelegationKey_PRE2 *delegationKey = new DelegationKey_PRE2;
	  
	  if (PRE2_delegate(*cp, *pk2, *sk1, *delegationKey) == FALSE) {
	    error = ERROR_NONE;
      }
	  *delKey = (void*)delegationKey;
    }
    break;
  }

  return error;
}

// proxylib_serializeDelegationKey()
//
// Serializes a pair of keys into a buffer.

int
proxylib_serializeDelegationKey(void *params, void *delKey, char *delKeyBuf,
	int *delKeyBufSize, int bufferAvailSize, SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  
  CurveParams *cp = (CurveParams*)params;
  switch(schemeID) {
  case SCHEME_PRE1:
	DelegationKey_PRE1 *dk = (DelegationKey_PRE1*)delKey;
	*delKeyBufSize = SerializeDelegationKey_PRE1(*dk, SERIALIZE_BINARY, delKeyBuf, bufferAvailSize);
	if (*delKeyBufSize > 0) { error = ERROR_NONE; }
	break;
  case SCHEME_PRE2:
	DelegationKey_PRE2 *dk = (DelegationKey_PRE2*)delKey;
	*delKeyBufSize = SerializeDelegationKey_PRE2(*dk, SERIALIZE_BINARY, delKeyBuf, bufferAvailSize);
	if (*delKeyBufSize > 0) { error = ERROR_NONE; }
    break;
  }

  return error;
}

// proxylib_deserializeDelegationKey()
//
// Deserializes a buffer of parameters and returns a newly-allocated buffer.

int
proxylib_deserializeParams(char *buffer, int bufferSize, void **delKey,
		SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  
  switch(schemeID) {
	case SCHEME_PRE1:
		DelegationKey_PRE1 *dk = new DelegationKey_PRE1;
		if (DeserializeDelegationKey_PRE1(*dk, SERIALIZE_BINARY, 
			buffer, bufferSize) == FALSE) {
			delete dk;
			*delKey = NULL;
		} else {
			error = ERROR_NONE;
			*delKey = (void*)dk;
		}
		break;
	case SCHEME_PRE2:
		DelegationKey_PRE2 *dk = new DelegationKey_PRE2;
		if (DeserializeDelegationKey_PRE2(*dk, SERIALIZE_BINARY, 
			buffer, bufferSize) == FALSE) {
			delete dk;
			*delKey = NULL;
		} else {
			error = ERROR_NONE;
			*delKey = (void*)dk;
		}
		break;
	}
  
  return error;
}

// proxylib_destroyKeys()
//
// Destroy a public or secret key.

int
proxylib_destroyDelegationKey(void *delKey, SCHEME_TYPE schemeID)
{
  int error = ERROR_NONE;
  
  switch(schemeID) {
  case SCHEME_PRE1:
    {  
		if (delKey != NULL) {
			DelegationKey_PRE1 *dk = (DelegationKey_PRE1*)delKey;
			delete dk;
		}
	}
	break;

  case SCHEME_PRE2:
    {
		if (delKey != NULL) {
			DelegationKey_PRE2 *dk = (DelegationKey_PRE2*)delKey;
			delete dk;
		}
	}
	break;
  }

  return error;
}

// proxylib_reencrypt()
//
// Re-encryps a ciphertext given a re-encryption key.  Outputs the
// result to a new buffer.

int
proxylib_reencrypt(void *params, void *rk, 
		   char *ciphertext, int ciphLen, 
		   char *newciphertext, int *newCiphLen, SCHEME_TYPE schemeID)
{
  int error = ERROR_OTHER;
  CurveParams *cp = (CurveParams *)params;

  switch(schemeID) {
  case SCHEME_PRE1:
    {
      // Deserialize the original ciphertext
      ProxyCiphertext_PRE1 ctext;
      ProxyCiphertext_PRE1 newctext;
      if (ctext.deserialize(SERIALIZE_BINARY, ciphertext, ciphLen) ==
	  FALSE) {
		return ERROR_OTHER;
      }

	  // Reencrypt the ciphertext using the re-encryption key
      DelegationKey_PRE1 *delKey = (DelegationKey_PRE1 *)rk;
	  if (PRE1_reencrypt(*cp, ctext, *delKey, newctext) == FALSE) {
			return ERROR_OTHER;
      }
	  
	  // Serialize the re-encrypted ciphertext
      *newCiphLen = newctext.serialize(SERIALIZE_BINARY, newciphertext, *newCiphLen);
      if (*newCiphLen > 0) {
		error = ERROR_NONE;
      } 
    }
    break;
  case SCHEME_PRE2: 
    {
      // Deserialize the original ciphertext
      ProxyCiphertext_PRE2 ctext;
      ProxyCiphertext_PRE2 newctext;
      if (ctext.deserialize(SERIALIZE_BINARY, ciphertext, ciphLen) ==
	  FALSE) {
		return ERROR_OTHER;
      }

	  // Reencrypt the ciphertext using the re-encryption key
      DelegationKey_PRE2 *delKey = (ECn *)rk;
	  if (PRE2_reencrypt(*cp, ctext, *delKey, newctext) == FALSE) {
			return ERROR_OTHER;
      }
	  
	  // Serialize the re-encrypted ciphertext
      *newCiphLen = newctext.serialize(SERIALIZE_BINARY, newciphertext, *newCiphLen);
      if (*newCiphLen > 0) {
		error = ERROR_NONE;
      } 
    }
    break;
  default:
    return ERROR_OTHER;
  }

  return error;
}
