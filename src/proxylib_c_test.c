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

#include <sys/time.h>

#include "proxylib_api.h"

#define NUMENCRYPTIONS 100

void *gParams, *gParams2;
int testNum = 0, testsSuccess = 0;

//
// Main routine for tests
//

int main()
{
	int err;
	char plaintext1[20] = "0123456789ABCDEF";
	char plaintext2[20] = "0000000000000000";
	char ciphertext1[20] = "";
	char ciphertext2[20] = "";
	int ptextLen1 = 16;
	int ptextLen2 = 16;
	int ctextLen1 = 0;
	int ctextLen2 = 0;
    char buffer[1000];
    void *newParams = NULL;

	printf("Proxy Re-encryption Library\nDiagnostic Test Routines (C language)\n\n");

  /*
   * Initialize library test
   */
  printf("%d. Initializing library", ++testNum);
  err = proxylib_initLibrary(char *seedbuf, int bufsize);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    printf(" ... OK\n");
    testsSuccess++;
  }

  /****************/
  /* PRE1 Tests   */
  /****************/

  printf("\nTESTING PRE1 ROUTINES\n\n");
  /*
   * Parameter generation test
   */
  printf("%d. Generating curve parameters ", ++testNum);
  err = proxylib_generateParams(&gParams, SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    printf(" ... OK\n");
    testsSuccess++;
  }

  /*
   * Key generation tests
   */
  printf("%d. Generating keypair 1 ", ++testNum);
  void *sk1 = NULL;
  void *pk1 = NULL;
  err = proxylib_generateKeys(gParams, &pk1, &sk2, SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    printf(" ... OK\n");
    testsSuccess++;
  }

  printf("%d. Generating keypair 2 ", ++testNum);
  void *sk2 = NULL;
  void *pk2 = NULL;
  err = proxylib_generateKeys(gParams, &pk1, &sk2, SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    printf(" ... OK\n");
    testsSuccess++;
  }

  /*
   * Re-encryption key generation test
   */
  printf("%d. Re-encryption key generation test ", ++testNum);
  void* delKey = NULL;
  /* Generate a delegation key from user1->user2 */
  err = proxylib_generateDelegationKey(gParams, sk1, pk2, &delKey, 
		      SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    printf(" ... OK\n");
    testsSuccess++;
  }

  /*
   * First-level encryption/decryption test
   */
  printf("%d. First-level encryption/decryption test ", ++testNum);
  err = proxylib_encrypt(gParams, pk1, (char*)plaintext1, ptextLen1, 
		 ciphertext1, ctextLen1, CIPH_FIRST_LEVEL,
		 SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    // Decrypt the ciphertext
	err = proxylib_decrypt(gParams, sk1, plaintext2, &ptextLen2, 
		 ciphertext1, ctextLen1, SCHEME_PRE1);
    if (err != ERROR_NONE) {
		printf(" ... FAILED (error %d)\n", err);
    } else {
      if ((ptextLen1 != ptextLen2) || (memcmp(plaintext1, plaintext2, ptextLen1) != 0) {
		printf(" ... FAILED (plaintexts don't match)\n", err);
      } else {
		printf(" ... OK\n");
		testsSuccess++;
      }
    }
  }

  /*
   * Second-level encryption/decryption test
   */
  strcpy(plaintext1, "0123456789ABCDEF");
  strcpy(plaintext2, "0000000000000000");
  ptextLen1 = ptextLen2 = 16;
  printf("%d. Second-level encryption/decryption test ", ++testNum);
  err = proxylib_encrypt(gParams, pk1, (char*)plaintext1, ptextLen1, 
		 ciphertext1, ctextLen1, CIPH_SECOND_LEVEL,
		 SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (error %d)\n", err);
  } else {
    // Decrypt the ciphertext
	err = proxylib_decrypt(gParams, sk1, plaintext2, &ptextLen2, 
		 ciphertext1, ctextLen1, SCHEME_PRE1);
    if (err != ERROR_NONE) {
		printf(" ... FAILED (error %d)\n", err);
    } else {
      if ((ptextLen1 != ptextLen2) || (memcmp(plaintext1, plaintext2, ptextLen1) != 0) {
		printf(" ... FAILED (plaintexts don't match)\n", err);
      } else {
		printf(" ... OK\n");
		testsSuccess++;
      }
    }
  }

  /*
   * Re-encryption/decryption test
   */
  printf("%d. Re-encryption/decryption test ", ++testNum);
  /* Re-encrypt ciphertext from user1->user2 using delKey 
   * We make use of the ciphertext generated in the previous test. */
  err = proxylib_reencrypt(gParams, delKey, ciphertext1, ctextLen1, ciphertext2, 
	ctextLen2, SCHEME_PRE1);
  if (err != ERROR_NONE) {
	printf(" ... FAILED (error %d)\n", err);
  } else {
    /* Decrypt the ciphertext using sk2 */
	err = proxylib_decrypt(gParams, sk2, plaintext2, &ptextLen2, 
		 ciphertext2, ctextLen2, SCHEME_PRE1);
	if (err = ERROR_NONE) {
		printf(" ... FAILED (error %d)\n", err);
    } else {
      if ((ptextLen1 != ptextLen2) || (memcmp(plaintext1, plaintext2, ptextLen1) != 0) {
		printf(" ... FAILED (plaintexts don't match)\n", err);
      } else {
		printf(" ... OK\n");
		testsSuccess++;
      }
    }
  }

  /*
   * Serialization/Deserialization test
   */
  BOOL serTestResult = TRUE;
  printf("%d. Serialization/deserialization tests\n", ++testNum);
  
  /* Serialize a public/secret keypair */
  err = proxylib_serializeKeys(gParams, pk1, sk1, buffer1, buffer2,
	&bufsize1, &bufsize2, 1000, SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (serialize keys, error %d)\n", err);
  }
  
  err = proxylib_deserializeKeys(gParams, buffer1, buffer2,
	bufsize1, bufsize2, &pk2, &pk2, SCHEME_PRE1);
  if (err != ERROR_NONE) {
    printf(" ... FAILED (deserialize keys, error %d)\n", err);
  }
  
  /* Serialize a delegation key */
  /* TODO */
  
  /* Serialize curve parameters */
  err = proxylib_serializeParams(gParams, buffer, &bufferSize, 1000, SCHEME_PRE1);
  if (err != ERROR_NONE) {
	printf(" ... FAILED (error %d)\n", err);
  } else {
	err = proxylib_deserializeParams(buffer, bufferSize, &gParams2, SCHEME_PRE1);
    if (err != ERROR_NONE) {
	  printf(" ... FAILED (error %d)\n", err);
	}
  }
  /*serTestResult = serTestResult && (newParams == gParams);*/

  if (serTestResult == TRUE) {
	printf(" ... FAILED\n", err);
  } else {
	printf(" ... OK\n");
	testsSuccess++;
  }

  cout << endl << "All tests complete." << endl;
  cout << testsSuccess << " succeeded out of " <<
    testNum << " total." << endl;
}
