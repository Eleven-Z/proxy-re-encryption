// pairing_keygen.cpp
//
// Command line utility for generating new keypairs for use in
// the pairing-based re-encryption scheme.
//
// Requires: zzn2.cpp big.cpp monty.cpp elliptic.cpp

#include <iostream>
#include <fstream>
#include <cstring>
#include "elliptic.h"
#include "monty.h"
#include "zzn2.h"

using namespace std;

#include "pairing.h"

extern Miracl precision;

int main()
{
    ECn P,Ppub1, Ppub2, Q;
    ZZn2 cube;
    Big s,s1,s2,p,q,t,n,cof,x,y;
    long seed;
    miracl *mip=&precision;
    ZZn2 Zpub1;
    int bits;
    CurveParams params;

    cout << "This program generates a new random public and private keypair" << endl;
    cout << "for an system user." << endl;
    cout << "Enter 9 digit random number seed  = ";
    cin >> seed;
    irand(seed);

    ReadParamsFile("publicparams.cfg", params);

    char prefix[1000];
    cout << "Enter the filename prefix for the key files:" << endl;
    cin.get();
    cin.getline(prefix,1000);

//
// Pick random secret key (s1, s2), and partial public key (s2)P
//    
    s1=rand(params.q);
    s2=rand(params.q);
    Q=s1*params.P;
    Ppub2=s2*params.P;

//
// Compute the value Z^s1 = e(P, Q = P^s1) using the Tate pairing
//    
    if (ecap(params.P, Q, params.q, params.cube, Zpub1) == FALSE) {
      cout << "Pairing computation failed.  Please try again with a different seed." << endl;
      exit(1);
    }
    cout << "Secret Key s1=" << s1 << endl;
    cout << "Secret Key s2=" << s2 << endl;
    cout << "Public Key p1=" << Zpub1 << endl;
    cout << "Public Key p2=" << Ppub2 << endl;

    // open output files
    char filename[1000];
    strcpy(filename, prefix);
    strcat(filename, ".bp.pub.key");
    ofstream pubfile(filename);
    strcpy(filename, prefix);
    strcat(filename, ".bp.pri.key");
    ofstream secretfile(filename);

    mip->IOBASE=16;
    Zpub1.get(x,y);
    pubfile << x << endl;
    pubfile << y << endl;
    Ppub2.get(x,y);
    pubfile << x << endl;
    pubfile << y << endl;

    secretfile << s1 << endl;    
    secretfile << s2 << endl;

    return 0;
}
