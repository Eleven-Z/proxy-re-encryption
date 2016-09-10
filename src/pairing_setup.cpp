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
