// benchmark.cpp
//
// Collects benchmark statistics

#include <iostream>
#include <fstream>
#include <cstring>

#include <iostream>
#include <fstream>
#include <cstring>
#include "ecn.h"
#include "zzn2.h"

using namespace std;
#include "proxylib_api.h"
#include "proxylib.h"
#include "proxylib_benchmark.h"

//
// Benchmark initialization
//

void InitBenchmarks(Benchmark &benchmark, long numOps)
{
  benchmark.InitOp(LEVELONEENCTIMING, numOps, LEVELONEENCDESC);
  benchmark.InitOp(LEVELTWOENCTIMING, numOps, LEVELTWOENCDESC);
  benchmark.InitOp(DELEGATETIMING, numOps, DELEGATEDESC);
  benchmark.InitOp(REENCTIMING, numOps, REENCDESC);
  benchmark.InitOp(LEVELONEDECTIMING, numOps, LEVELONEDECDESC);
  benchmark.InitOp(LEVELTWODECTIMING, numOps, LEVELTWODECDESC);
  benchmark.InitOp(REENCDECTIMING, numOps, REENCDECDESC);
}

BenchOp::~BenchOp()
{ 
  if (this->mTimings) {
    cout << "Deleting timings" << endl; 
    delete mTimings; 
  } 
}

double 
BenchOp::Mean() 
{ 
  if (this->mNumTimings==0) return -1; 
  double result=0.; 
  long validTimings = 0;
  for (long i=0; i < mNumTimings; i++) { 
    cout << mTimings[i] << endl;
    if (mTimings[i] >= 0) {
      result += mTimings[i];
      validTimings++;
    }
  } 

  return result / validTimings;
}

// InitOp()
//
// Set up the description and maximum number of timings for a given operation

BOOL
Benchmark::InitOp(int opnum, int maxTimings, char *description)
{
  if (opnum < this->mNumops) {
    this->mStats[opnum].SetMaxTimings(maxTimings);
    this->mStats[opnum].SetDescription(description);
    return TRUE;
  }

  return FALSE;
}

// CollectTiming()
//
// Collects a timing value for a given operation

BOOL
Benchmark::CollectTiming(int opnum, long microseconds)
{
  if (opnum < mNumops) {
    this->mStats[opnum].AddTiming(microseconds);
    return TRUE;
  }

  return FALSE;
}

BOOL
Benchmark::GetStats(int opnum, double &mean, double &median, double &stddev)
{
  if (opnum > mNumops) {
    return FALSE;
  }

  mean = this->mStats[opnum].Mean();
  median = this->mStats[opnum].Median();
  stddev = this->mStats[opnum].StdDev();
}

ostream& operator<<(ostream& s, const Benchmark &benchmark)
{
  double mean, median = 0, stddev = 0;
  char *description;

  s << "Benchmark Results" << endl;
  for (int i = 0; i < benchmark.mNumops; i++) {
    //benchmark.GetStats(i, mean, median, stddev);
    //description = benchmark.GetDescription(i);
    mean = benchmark.mStats[i].Mean();
    description = benchmark.mStats[i].mDesc;

    s << "Operation " << i << " (" << description << "): mean="
      << mean << ", median=" << median << ", stddev=" << stddev << endl;
  }
}

//
// General routines for timing
//

// CalculateUsecs()
//
// Return the number of elapsed microseconds between two timeval
// structs

long
CalculateUsecs(struct timeval &tstart, struct timeval &tend)
{
  long result;

  if (tstart.tv_usec > tend.tv_usec) {
    result = tend.tv_usec + USECS_PER_SECOND;
    return result - tstart.tv_usec;
  }

  return tend.tv_usec - tstart.tv_usec;
}
