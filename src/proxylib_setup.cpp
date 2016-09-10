// The JHU-MIT Proxy Re-encryption Library (PRL)
//
// proxylib_setup.cpp: Routines for generating global
// parameters shared by PRE keys.
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

// pairing_setup.cpp
//
// Command line utility for generating global elliptic curve
// parameters for use by the proxy.  Based on code from the IBE
// portion of the MIRACL library.
//
// Generates a file "publicparams.cfg" that contains:
//   
// <Size of prime modulus in bits>
// <Prime p>
// <Prime q (divides p+1) >
// <Point P - x coordinate>
// <Point P - y coordinate>
// <Point Ppub - x coordinate>
// <Point Ppub - y coordinate>
// <Cube root of unity in Fp2 - x component >
// <Cube root of unity in Fp2 - y component >
//
// Also generates a file "secretparams.cfg" that contains:
//
// <The master secret s>
//
// NOTE: define SIMPLE below to use a "simple" fixed group order q
//       with the minimum number of 1's. Here we use q=2^159+2^17+1
//
// Requires: zzn2.cpp big.cpp monty.cpp elliptic.cpp

#include <iostream>
#include <fstream>
#include <cstring>
#include "elliptic.h"
#include "monty.h"
#include "zzn2.h"

using namespace std;
extern Miracl precision;

#include "pairing.h"

int main()
{
    ofstream common("publicparams.cfg");
    ofstream masterpub("master.bp.pub.key");
    ofstream masterpri("master.bp.pri.key");
    ECn P,Ppub1, Ppub2, Q;
    ZZn2 cube;
    Big s,s1,s2,p,q,t,n,cof,x,y;
    long seed;
    miracl *mip=&precision;
    ZZn2 Zpub1;

    cout << "This program generates public and private parameters for" << endl;
    cout << "the pairing-based re-encryption scheme, including the master" << endl;
    cout << "secret and public keypair.  The results are stored in the " << endl;
    cout << "file \"publicparams.cfg\"" << endl;
    cout << "Also generates the master and secret key in \"master.bp.pri.key\"" << endl;
    cout << "and \"master.bp.pub.key\"." << endl;
    cout << "Enter 9 digit random number seed  = ";
    cin >> seed;
    irand(seed);

// SET-UP

#ifdef SIMPLE

    q=pow((Big)2,159)+pow((Big)2,17)+1;
//    q=pow((Big)2,160)-pow((Big)2,76)-1;

#else

// generate random q 

    forever
    {
        n=rand(QBITS-1,2);  // 159 bit number, base 2 
        q=2*n+1;            // 160 bit
        while (!prime(q)) q+=2;
        if (bits(q)>QBITS) continue;
        break;
    }

#endif

    cout << "q= " << q << endl;

// generate p 
    t=(pow((Big)2,PBITS)-1)/(2*q);
    s=(pow((Big)2,PBITS-1)-1)/(2*q);
    forever 
    {
        n=rand(t);
        if (n<s) continue;
        p=2*n*q-1;
//        if (p%24!=5) continue;  // could be 2 mod 3, also 5 mod 8
        if (p%12!=11) continue;  // must be 2 mod 3, also 3 mod 4
        if (prime(p)) break;
    } 
    cout << "p= " << p << endl;
    //global_p = p;
    //cout << "global_p= " << global_p << endl;

    cof=2*n;

// elliptic curve y^2=x^3+1 mod p
#ifdef AFFINE
    ecurve(0,1,p,MR_AFFINE);   
#endif
#ifdef PROJECTIVE
    ecurve(0,1,p,MR_PROJECTIVE);
#endif

//
// Find suitable cube root of unity (solution in Fp2 of x^3=1 mod p)
//    
    forever
    {
    //    cube=pow(randn2(),(p+1)*(p-1)/3);
        cube=pow(randn2(),(p+1)/3);
        cube=pow(cube,p-1);
        if (!cube.isunity()) break;
    }
    
    cout << "Cube root of unity= " << cube << endl;

    if (!(cube*cube*cube).isunity())
    {
        cout << "sanity check failed" << endl;
        exit(0);
    }
//
// Choosing an arbitrary P ....
//
    forever
    {
        while (!P.set(randn())) ;
        P*=cof;
        if (!P.iszero()) break;
    }

    cout << "Point P= " << P << endl;

//
// Pick a random master private key (s1, s2) 
//    
    s1=rand(q);
    s2=rand(q);
    Q=s1*P;
    Ppub2=s2*P;

//
// Compute the value Z^s1 = e(P, Q = P^s1) using the Tate pairing
//    
    if (ecap(P, Q, q, cube, Zpub1) == FALSE) {
      cout << "Pairing computation failed.  Please try again with a different seed." << endl;
      exit(1);
    }

    ZZn2 Zprecomp, Zexp;
    if (ecap(P, P, q, cube, Zprecomp) == FALSE) {
      cout << "Unable to compute Z." << endl;
    }
    Zexp = pow(Zprecomp, s1);

    cout << "Secret Key s1=" << s1 << endl;
    cout << "Secret Key s2=" << s2 << endl;
    cout << "Public Key p1=" << Zpub1 << endl;
    cout << "Public Key p2=" << Ppub2 << endl;
    cout << "Z= " << Zprecomp << endl;
    cout << "Z^s1= " << Zexp << endl;

    common << PBITS << endl;
    mip->IOBASE=16;
    common << p << endl;
    common << q << endl;
    P.get(x,y);
    common << x << endl;
    common << y << endl;
    cube.get(x,y);
    common << x << endl;
    common << y << endl;
    Zprecomp.get(x, y);
    common << x << endl;
    common << y << endl;

    // Write the master public and secret key
    Zpub1.get(x,y);
    masterpub << x << endl;
    masterpub << y << endl;
    Ppub2.get(x,y);
    masterpub << x << endl;
    masterpub << y << endl;

    masterpri << s1 << endl;    
    masterpri << s2 << endl;

    return 0;
}
