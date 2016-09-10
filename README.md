# PRE-Library
The modified version of the JHU-MIT Proxy Recryptography Library (https://isi.jhu.edu/~mgreen/prl/index.html).

The JHU-MIT is a very famous implementation of Proxy Re-encryption (PRE) Library, the core of which is a C++ implementation of the proxy re-encryption schemes proposed by Giuseppe Ateniese, Kevin Fu, Matthew Green and Susan Hohenberger in NDSS 2005. But due to ages, too many errors will appear compiling it today. This is a small modified version to be successfully compiled. Thanks to the contribution of original authors.

This PRE-Library is distributed in source-code form, and is targeted for Linux
platform.

Requirements:
1. Obtain the MIRACL library miracl3.zip from http://www3.cs.stonybrook.edu/~algorith/implement/shamus/distrib/
. Unzip and build the library archive file using
the following commands:

 --> mkdir miracl/
 --> mv miracl3.zip miracl/
 --> cd miracl/
 --> unzip -j -aa -L miracl3.zip miracl/
 --> bash linux64 % For 64bits system
 
 Then, miracl.a will be generated in miracl/. Some examples were also compiled and you can run them to verify the miracl.a, e.g. hail, pk_demo. Note that It must be miracl3, not the latest version!
 
 2. Untar the file prelib.tar.gz in the same base directory in which
you created the miracl/ directory (parallel to miracl/). Next, build the library
via the following commands:
--> tar -zxvf prelib.tar.gz  % decompress to proxylib/
--> cd proxylib/src/
--> make clean
--> make all  % Re-build the miracl.a, proxylib.a and proxylib_test. Run ./proxylib_test to verify.
