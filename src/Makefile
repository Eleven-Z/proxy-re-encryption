MIRACLPATH = ../../miracl
CC = g++
CCFLAGS = -I${MIRACLPATH} -O2  
CCLIBS = -lstdc++
AR = ar
ARARGS = rcs
PROXYLIB = proxylib.a
PROXYLIBWITHMIRACL = proxylibmiracl.a
MIRACLLIBRARY = ${MIRACLPATH}/miracl.a 
MIRACLCPP = ${MIRACLPATH}/zzn2.cpp ${MIRACLPATH}/big.cpp \
	    ${MIRACLPATH}/ecn.cpp
 
PROXYLIBTEST = proxylib_test
PROXYLIBTESTOBJ = proxylib_test.o
PROXYLIBTESTH =
PROXYLIBTESTWITHMIRACL = proxylib_test_withmiracl

LIBRARYOBJ = proxylib_utilities.o proxylib_pre1.o proxylib_benchmark.o \
	proxylib_pre2.o \
	${MIRACLPATH}/zzn.o ${MIRACLPATH}/zzn2.o ${MIRACLPATH}/big.o \
	${MIRACLPATH}/ecn.o
LIBRARYH = proxylib.h proxylib_pre1.h proxylib_benchmark.h proxylib_pre2.h \
	proxylib_api.h

all: ${MIRACLLIBRARY} ${PROXYLIB} proxylib_test
withmiracl: ${MIRACLLIBRARY} ${PROXYLIBWITHMIRACL}

${MIRACLLIBRARY}:
	#cd ${MIRACLPATH}; bash linux; cd -
	#Jet: For my linux 64bits system@20160908
	cd ${MIRACLPATH}; bash linux64; cd -

${PROXYLIB}: ${MIRACLLIBRARY} ${LIBRARYOBJ} ${LIBRARYH}
	${CC} ${CCFLAGS} -o ${MIRACLPATH}/zzn2.o -c ${MIRACLPATH}/zzn2.cpp 	
	${AR} ${ARARGS} ${PROXYLIB} ${LIBRARYOBJ}

${PROXYLIBWITHMIRACL}: ${MIRACLLIBRARY} ${PROXYLIB}
	rm -f temp/*.o
	cd temp; ${AR} x ../${MIRACLLIBRARY}; cd -
	${AR} ${ARARGS} ${PROXYLIBWITHMIRACL} ${LIBRARYOBJ} temp/*.o
	rm -f temp/*.o

${PROXYLIBTEST}: ${PROXYLIB} ${PROXYLIBTESTOBJ} ${PROXYLIBTESTH}
	${CC} ${CCFLAGS} ${CCLIBS} -o ${PROXYLIBTEST} ${PROXYLIBTESTOBJ} ${PROXYLIB} ${MIRACLLIBRARY}

${PROXYLIBTESTWITHMIRACL}: ${PROXYLIBWITHMIRACL} ${PROXYLIBTESTOBJ} ${PROXYLIBTESTH}
	${CC} ${CCFLAGS} ${CCLIBS} -o ${PROXYLIBTESTWITHMIRACL} ${PROXYLIBTESTOBJ} ${PROXYLIBWITHMIRACL}
 
#pairingsetup: ${PAIRINGSETUPOBJ} ${PAIRINGSETUPH} ${MIRACLLIBRARY}
#	${CC} ${CCFLAGS} ${CCLIBS} -o pairingsetup ${PAIRINGSETUPOBJ} \
#		${MIRACLCPP} ${MIRACLEXTRAS} ${MIRACLLIBRARY}

#pairingkeygen: ${PAIRINGKEYGENOBJ} ${PAIRINGKEYGENH} ${MIRACLLIBRARY}
#	${CC} ${CCFLAGS} ${CCLIBS} -o pairingkeygen ${PAIRINGKEYGENOBJ} \
#		${MIRACLCPP} ${MIRACLEXTRAS} ${MIRACLLIBRARY}

#pairingenctest: ${PAIRINGENCTESTOBJ} ${PAIRINGENCTESTH} ${MIRACLLIBRARY}
#	${CC} ${CCFLAGS} ${CCLIBS} -o pairingenctest ${PAIRINGENCTESTOBJ} \
#		${MIRACLCPP} ${MIRACLEXTRAS} ${MIRACLLIBRARY}

#pdtsetup: ${PDTSETUPOBJ} ${PDTSETUPH} ${MIRACLLIBRARY}
#	${CC} ${CCFLAGS} ${CCLIBS} -o pdtsetup ${PDTSETUPOBJ} \
#		${MIRACLCPP} ${MIRACLEXTRAS} ${MIRACLLIBRARY}

#library: ${LIBRARYOBJ}
#	/usr/bin/ar cq proxyfs.a ${LIBRARYOBJ}

clean:
	rm -rf *.o a.out ${MIRACLPATH}/miracl.a proxylib.a

%.o: %.c
	${CC} ${CCFLAGS} -c $<

%.o: %.cpp
	${CC} ${CCFLAGS} -c $<

%.h:
