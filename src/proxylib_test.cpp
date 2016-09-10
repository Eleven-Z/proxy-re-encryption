// The JHU-MIT Proxy Re-encryption Library (PRL)
//
// proxylib_test.cpp: Diagnostic test program. Links to the proxylib.a
// library to evaluate the functionality.
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

#ifdef BENCHMARKING
static struct timeval gTstart, gTend;
static struct timezone gTz;
extern Benchmark gBenchmark;
#endif

#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/time.h>

using namespace std;

#include "proxylib.h"
#include "proxylib_pre1.h"

#define NUMENCRYPTIONS 100

// Jet: the following causes segmentation fault
// move it inside the main function.
//static CurveParams gParams;
int testNum = 0, testsSuccess = 0;

#ifdef BENCHMARKING
Benchmark gBenchmark(NUMBENCHMARKS);
#endif

//
// Main routine for tests
//

int main()
{
  cout << "Proxy Re-encryption Library" << endl << "Diagnostic Test Routines" << endl
       << endl;

// Jet: declare here to avoid segmentation fault
  CurveParams gParams;
  //
  // Initialize library test
  //
  cout << ++testNum << ". Initializing library";
  if (initLibrary() == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  // ******
  // PRE1 Tests
  // ******

  cout << endl << "TESTING PRE1 ROUTINES" << endl << endl;
  //
  // Parameter generation test
  //
  cout << ++testNum << ". Generating curve parameters";
  if (PRE1_generate_params(gParams) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  //
  // Key generation tests
  //
  cout << ++testNum << ". Generating keypair 1";
  ProxyPK_PRE1 pk1;
  ProxySK_PRE1 sk1;
  if (PRE1_keygen(gParams, pk1, sk1) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  cout << ++testNum << ". Generating keypair 2";
  ProxyPK_PRE1 pk2;
  ProxySK_PRE1 sk2;
  if (PRE1_keygen(gParams, pk2, sk2) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  //
  // Re-encryption key generation test
  //
  cout << ++testNum << ". Re-encryption key generation test ";
  ECn delKey;
  // Generate a delegation key from user1->user2
  if (PRE1_delegate(gParams, pk2, sk1, delKey) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  //
  // First-level encryption/decryption test
  //
  cout << ++testNum << ". First-level encryption/decryption test ";
  Big plaintext1 = 100;
  Big plaintext2 = 0;
  ProxyCiphertext_PRE1 ciphertext;
  if (PRE1_level1_encrypt(gParams, plaintext1, pk1, ciphertext) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    // Decrypt the ciphertext
    if (PRE1_decrypt(gParams, ciphertext, sk1, plaintext2) == FALSE) {
      cout << " ... FAILED" << endl;
    } else {
      if (plaintext1 != plaintext2) {
	cout << " ... FAILED" << endl;
      } else {
	cout << " ... OK" << endl;
	testsSuccess++;
      }
    }
  }

  //
  // Second-level encryption/decryption test
  //
  cout << ++testNum << ". Second-level encryption/decryption test ";
  plaintext1 = 100;
  plaintext2 = 0;
  if (PRE1_level2_encrypt(gParams, plaintext1, pk1, ciphertext) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    // Decrypt the ciphertext
    if (PRE1_decrypt(gParams, ciphertext, sk1, plaintext2) == FALSE) {
      cout << " ... FAILED" << endl;
    } else {
      if (plaintext1 != plaintext2) {
	cout << " ... FAILED" << endl;
      } else {
	cout << " ... OK" << endl;
	testsSuccess++;
      }
    }
  }

  //
  // Re-encryption/decryption test
  //
  ProxyCiphertext_PRE1 newCiphertext;
  plaintext2 = 0;
  cout << ++testNum << ". Re-encryption/decryption test ";
  // Re-encrypt ciphertext from user1->user2 using delKey
  // We make use of the ciphertext generated in the previous test.
  if (PRE1_reencrypt(gParams, ciphertext, delKey, newCiphertext) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    // Decrypt the ciphertext
    if (PRE1_decrypt(gParams, newCiphertext, sk2, plaintext2) == FALSE) {
      cout << " ... FAILED" << endl;
    } else {
      if (plaintext1 != plaintext2) {
	cout << " ... FAILED" << endl;
      } else {
	cout << " ... OK" << endl;
	testsSuccess++;
      }
    }
  }

  // 
  // Proxy non-invisibility (negative) test
  //
  // We take the re-encrypted ciphertext from the previous test
  // and relabel it as a first-level ciphertext.  In PRE1 the
  // first-level and re-encrypted ciphertexts have different
  // forms, and hence the ciphertext should decrypt incorrectly.
  //
  cout << ++testNum << ". Proxy non-invisibility test ";
  newCiphertext.type = CIPH_FIRST_LEVEL;
  // Decrypt the ciphertext
  if (PRE1_decrypt(gParams, newCiphertext, sk2, plaintext2) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    if (plaintext1 == plaintext2) {
      cout << " ... FAILED" << endl;
    } else {
      cout << " ... OK" << endl;
      testsSuccess++;
    }
  }

  //
  // Serialization/Deserialization test
  //
  BOOL serTestResult = TRUE;
  cout << ++testNum << ". Serialization/deserialization tests";
  char buffer[1000];
  
  // Serialize a public key
  int serialSize = pk1.serialize(SERIALIZE_BINARY, buffer, 1000);
  ProxyPK_PRE1 newpk;
  newpk.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (newpk == pk1);

  // Serialize a secret key
  serialSize = sk1.serialize(SERIALIZE_BINARY, buffer, 1000);
  ProxySK_PRE1 newsk;
  newsk.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (newsk == sk1);

  // Serialize a ciphertext
  serialSize = newCiphertext.serialize(SERIALIZE_BINARY, buffer, 1000);
  ProxyCiphertext_PRE1 newerCiphertext;
  newerCiphertext.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (newerCiphertext == newCiphertext);

  // Serialize curve parameters
  serialSize = gParams.getSerializedSize(SERIALIZE_BINARY);
  serialSize = gParams.serialize(SERIALIZE_BINARY, buffer, 1000);
  CurveParams newParams;
  newParams.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (newParams == gParams);

  if (serTestResult == TRUE) {
    cout << " ... OK" << endl;
    testsSuccess++;
  } else {
    cout << " ... FAILED" << endl;
  }
  
  // ******
  // PRE2 Tests
  // ******

  cout << endl << "TESTING PRE2 ROUTINES" << endl << endl;
  //
  // Parameter generation test
  //
  cout << ++testNum << ". Generating curve parameters";
  if (PRE2_generate_params(gParams) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  //
  // Key generation tests
  //
  cout << ++testNum << ". Generating keypair 1";
  ProxyPK_PRE2 ppk1;
  ProxySK_PRE2 ssk1;
  if (PRE2_keygen(gParams, ppk1, ssk1) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  cout << ++testNum << ". Generating keypair 2";
  ProxyPK_PRE2 ppk2;
  ProxySK_PRE2 ssk2;
  if (PRE2_keygen(gParams, ppk2, ssk2) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }


  //
  // Re-encryption key generation test
  //
  cout << ++testNum << ". Re-encryption key generation test ";
  // Generate a delegation key from user1->user2
  if (PRE2_delegate(gParams, ppk2, ssk1, delKey) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    cout << " ... OK" << endl;
    testsSuccess++;
  }

  //
  // First-level encryption/decryption test
  //
  cout << ++testNum << ". First-level encryption/decryption test ";
  plaintext1 = 100;
  plaintext2 = 0;
  ProxyCiphertext_PRE2 cciphertext;
  if (PRE2_level1_encrypt(gParams, plaintext1, ppk1, cciphertext) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    // Decrypt the ciphertext
    if (PRE2_decrypt(gParams, cciphertext, ssk1, plaintext2) == FALSE) {
      cout << " ... FAILED" << endl;
    } else {
      if (plaintext1 != plaintext2) {
	cout << " ... FAILED" << endl;
      } else {
	cout << " ... OK" << endl;
	testsSuccess++;
      }
    }
  }

  //
  // Second-level encryption/decryption test
  //
  cout << ++testNum << ". Second-level encryption/decryption test ";
  plaintext1 = 100;
  plaintext2 = 0;
  if (PRE2_level2_encrypt(gParams, plaintext1, ppk1, cciphertext) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    // Decrypt the ciphertext
    if (PRE2_decrypt(gParams, cciphertext, ssk1, plaintext2) == FALSE) {
      cout << " ... FAILED" << endl;
    } else {
      if (plaintext1 != plaintext2) {
	cout << " ... FAILED" << endl;
      } else {
	cout << " ... OK" << endl;
	testsSuccess++;
      }
    }
  }

  //
  // Re-encryption test
  //
  ProxyCiphertext_PRE2 nnewCiphertext;
  plaintext2 = 0;
  cout << ++testNum << ". Re-encryption/decryption test ";
  // Re-encrypt ciphertext from user1->user2 using delKey
  if (PRE2_reencrypt(gParams, cciphertext, delKey, nnewCiphertext) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    // Decrypt the ciphertext
    if (PRE2_decrypt(gParams, nnewCiphertext, ssk2, plaintext2) == FALSE) {
      cout << " ... FAILED" << endl;
    } else {
      if (plaintext1 != plaintext2) {
	cout << " ... FAILED" << endl;
      } else {
	cout << " ... OK" << endl;
	testsSuccess++;
      }
    }
  }

  // 
  // Proxy invisibility test
  //
  // We take the re-encrypted ciphertext from the previous test
  // and mark it as a first-level ciphertext.  Decryption
  // should still work just fine.
  //
  cout << ++testNum << ". Proxy invisibility test ";
  nnewCiphertext.type = CIPH_FIRST_LEVEL;
  // Decrypt the ciphertext
  if (PRE2_decrypt(gParams, nnewCiphertext, ssk2, plaintext2) == FALSE) {
    cout << " ... FAILED" << endl;
  } else {
    if (plaintext1 != plaintext2) {
      cout << " ... FAILED" << endl;
    } else {
      cout << " ... OK" << endl;
      testsSuccess++;
    }
  }

  //
  // Serialization/Deserialization test
  //
  serTestResult = TRUE;
  cout << ++testNum << ". Serialization/deserialization tests";
  
  // Serialize a public key
  serialSize = ppk1.serialize(SERIALIZE_BINARY, buffer, 1000);
  ProxyPK_PRE2 nnewpk;
  nnewpk.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (nnewpk == ppk1);
  
  // Serialize a secret key
  serialSize = ssk1.serialize(SERIALIZE_BINARY, buffer, 1000);
  ProxySK_PRE2 nnewsk1;
  nnewsk1.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (nnewsk1 == ssk1);
  
  // Serialize a ciphertext
  serialSize = newCiphertext.serialize(SERIALIZE_BINARY, buffer, 1000);
  ProxyCiphertext_PRE2 nnewerCiphertext;
  nnewerCiphertext.deserialize(SERIALIZE_BINARY, buffer, serialSize);
  serTestResult = serTestResult && (newerCiphertext == newCiphertext);

  if (serTestResult == TRUE) {
    cout << " ... OK" << endl;
    testsSuccess++;
  } else {
    cout << " ... FAILED" << endl;
  }

  cout << endl << "All tests complete." << endl;
  cout << testsSuccess << " succeeded out of " <<
    testNum << " total." << endl;
}
