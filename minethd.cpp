/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

#include <assert.h>
#include <cmath>
#include <chrono>
#include <cstring>
#include <thread>
#include <bitset>
#include "console.h"

#ifdef _WIN32
#include <windows.h>

void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
	SetThreadAffinityMask(h, 1ULL << cpu_id);
}
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#endif


void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
#if defined(__APPLE__)
	thread_port_t mach_thread;
	thread_affinity_policy_data_t policy = { static_cast<integer_t>(cpu_id) };
	mach_thread = pthread_mach_thread_np(h);
	thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1);
#elif defined(__FreeBSD__)
	cpuset_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	pthread_setaffinity_np(h, sizeof(cpuset_t), &mn);
#else
	cpu_set_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn);
#endif
}
#endif // _WIN32

#include "executor.h"
#include "minethd.h"
#include "jconf.h"
#include "crypto/cryptonight_aesni.h"
#include "hwlocMemory.hpp"

telemetry::telemetry(size_t iThd)
{
	ppHashCounts = new uint64_t*[iThd];
	ppTimestamps = new uint64_t*[iThd];
	iBucketTop = new uint32_t[iThd];

	for (size_t i = 0; i < iThd; i++)
	{
		ppHashCounts[i] = new uint64_t[iBucketSize];
		ppTimestamps[i] = new uint64_t[iBucketSize];
		iBucketTop[i] = 0;
		memset(ppHashCounts[0], 0, sizeof(uint64_t) * iBucketSize);
		memset(ppTimestamps[0], 0, sizeof(uint64_t) * iBucketSize);
	}
}

double telemetry::calc_telemetry_data(size_t iLastMilisec, size_t iThread)
{
	using namespace std::chrono;
	uint64_t iTimeNow = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();

	uint64_t iEarliestHashCnt = 0;
	uint64_t iEarliestStamp = 0;
	uint64_t iLastestStamp = 0;
	uint64_t iLastestHashCnt = 0;
	bool bHaveFullSet = false;

	//Start at 1, buckettop points to next empty
	for (size_t i = 1; i < iBucketSize; i++)
	{
		size_t idx = (iBucketTop[iThread] - i) & iBucketMask; //overflow expected here

		if (ppTimestamps[iThread][idx] == 0)
			break; //That means we don't have the data yet

		if (iLastestStamp == 0)
		{
			iLastestStamp = ppTimestamps[iThread][idx];
			iLastestHashCnt = ppHashCounts[iThread][idx];
		}

		if (iTimeNow - ppTimestamps[iThread][idx] > iLastMilisec)
		{
			bHaveFullSet = true;
			break; //We are out of the requested time period
		}

		iEarliestStamp = ppTimestamps[iThread][idx];
		iEarliestHashCnt = ppHashCounts[iThread][idx];
	}

	if (!bHaveFullSet || iEarliestStamp == 0 || iLastestStamp == 0)
		return nan("");

	//Don't think that can happen, but just in case
	if (iLastestStamp - iEarliestStamp == 0)
		return nan("");

	double fHashes, fTime;
	fHashes = iLastestHashCnt - iEarliestHashCnt;
	fTime = iLastestStamp - iEarliestStamp;
	fTime /= 1000.0;

	return fHashes / fTime;
}

void telemetry::push_perf_value(size_t iThd, uint64_t iHashCount, uint64_t iTimestamp)
{
	size_t iTop = iBucketTop[iThd];
	ppHashCounts[iThd][iTop] = iHashCount;
	ppTimestamps[iThd][iTop] = iTimestamp;

	iBucketTop[iThd] = (iTop + 1) & iBucketMask;
}

minethd::minethd(miner_work& pWork, size_t iNo, bool double_work, bool no_prefetch, int64_t affinity)
{
	oWork = pWork;
	bQuit = 0;
	iThreadNo = (uint8_t)iNo;
	iJobNo = 0;
	iHashCount = 0;
	iTimestamp = 0;
	bNoPrefetch = no_prefetch;
	this->affinity = affinity;

	if(double_work)
		oWorkThd = std::thread(&minethd::penta_work_main, this);
	else
		oWorkThd = std::thread(&minethd::work_main, this);
}

std::atomic<uint64_t> minethd::iGlobalJobNo;
std::atomic<uint64_t> minethd::iConsumeCnt; //Threads get jobs as they are initialized
minethd::miner_work minethd::oGlobalWork;
uint64_t minethd::iThreadCount = 0;

cryptonight_ctx* minethd_alloc_ctx()
{
	cryptonight_ctx* ctx;
	alloc_msg msg = { 0 };

	switch (jconf::inst()->GetSlowMemSetting())
	{
	case jconf::never_use:
		ctx = cryptonight_alloc_ctx(1, 1, &msg);
		if (ctx == NULL)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		return ctx;

	case jconf::no_mlck:
		ctx = cryptonight_alloc_ctx(1, 0, &msg);
		if (ctx == NULL)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		return ctx;

	case jconf::print_warning:
		ctx = cryptonight_alloc_ctx(1, 1, &msg);
		if (msg.warning != NULL)
			printer::inst()->print_msg(L0, "MEMORY ALLOC FAILED: %s", msg.warning);
		if (ctx == NULL)
			ctx = cryptonight_alloc_ctx(0, 0, NULL);
		return ctx;

	case jconf::always_use:
		return cryptonight_alloc_ctx(0, 0, NULL);

	case jconf::unknown_value:
		return NULL; //Shut up compiler
	}

	return nullptr; //Should never happen
}

static constexpr size_t MAX_N = 5;

bool minethd::self_test()
{
	alloc_msg msg = { 0 };
	size_t res;
	bool fatal = false;

	switch (::jconf::inst()->GetSlowMemSetting())
	{
	case ::jconf::never_use:
		res = cryptonight_init(1, 1, &msg);
		fatal = true;
		break;

	case ::jconf::no_mlck:
		res = cryptonight_init(1, 0, &msg);
		fatal = true;
		break;

	case ::jconf::print_warning:
		res = cryptonight_init(1, 1, &msg);
		break;

	case ::jconf::always_use:
		res = cryptonight_init(0, 0, &msg);
		break;

	case ::jconf::unknown_value:
	default:
		return false; //Shut up compiler
	}

	if(msg.warning != nullptr)
		printer::inst()->print_msg(L0, "MEMORY INIT ERROR: %s", msg.warning);

	if(res == 0 && fatal)
		return false;

	cryptonight_ctx *ctx[MAX_N] = {0};
	for (int i = 0; i < MAX_N; i++)
	{
		if ((ctx[i] = minethd_alloc_ctx()) == nullptr)
		{
			printer::inst()->print_msg(L0, "ERROR: miner was not able to allocate memory.");
			for (int j = 0; j < i; j++)
				cryptonight_free_ctx(ctx[j]);
			return false;
		}
	}

	bool bResult = true;

	unsigned char out[32 * MAX_N];
	cn_hash_fun_multi hashf;
    #if 0
    hashf = func_multi_selector<1>(::jconf::inst()->HaveHardwareAes(), false);
    hashf("This is a test This is a test This is a test", 44, out, ctx);
    bResult = bResult &&  memcmp(out, "\x1\x57\xc5\xee\x18\x8b\xbe\xc8\x97\x52\x85\xa3\x6\x4e\xe9\x20\x65\x21\x76\x72\xfd\x69\xa1\xae\xbd\x7\x66\xc7\xb5\x6e\xe0\xbd", 32) == 0;

    hashf = func_multi_selector<1>(::jconf::inst()->HaveHardwareAes(), true);
    hashf("This is a test This is a test This is a test", 44, out, ctx);
    bResult = bResult &&  memcmp(out, "\x1\x57\xc5\xee\x18\x8b\xbe\xc8\x97\x52\x85\xa3\x6\x4e\xe9\x20\x65\x21\x76\x72\xfd\x69\xa1\xae\xbd\x7\x66\xc7\xb5\x6e\xe0\xbd", 32) == 0;
#else
    hashf = func_multi_selector<1>(::jconf::inst()->HaveHardwareAes(), false);
    hashf("This is a test This is a test This is a test", 44, out, ctx);
    bResult = memcmp(out, "\x35\x3f\xdc\x06\x8f\xd4\x7b\x03\xc0\x4b\x94\x31\xe0\x05\xe0\x0b\x68\xc2\x16\x8a\x3c\xc7\x33\x5c\x8b\x9b\x30\x81\x56\x59\x1a\x4f", 32) == 0;

    hashf = func_multi_selector<1>(::jconf::inst()->HaveHardwareAes(), true);
    hashf("This is a test This is a test This is a test", 44, out, ctx);
    bResult &= memcmp(out, "\x35\x3f\xdc\x06\x8f\xd4\x7b\x03\xc0\x4b\x94\x31\xe0\x05\xe0\x0b\x68\xc2\x16\x8a\x3c\xc7\x33\x5c\x8b\x9b\x30\x81\x56\x59\x1a\x4f", 32) == 0;
#endif
    if(!bResult)
         printer::inst()->print_msg(L0,
             "Cryptonight hash self-test failed. This might be caused by bad compiler optimizations.");

	for (int i = 0; i < MAX_N; i++)
		cryptonight_free_ctx(ctx[i]);

	return bResult;
}

std::vector<minethd*>* minethd::thread_starter(miner_work& pWork)
{
	iGlobalJobNo = 0;
	iConsumeCnt = 0;
	std::vector<minethd*>* pvThreads = new std::vector<minethd*>;

	//Launch the requested number of single and double threads, to distribute
	//load evenly we need to alternate single and double threads
	size_t i, n = jconf::inst()->GetThreadCount();
	pvThreads->reserve(n);

	jconf::thd_cfg cfg;
	for (i = 0; i < n; i++)
	{
		jconf::inst()->GetThreadConfig(i, cfg);

		minethd* thd = new minethd(pWork, i, cfg.bDoubleMode, cfg.bNoPrefetch, cfg.iCpuAff);
		pvThreads->push_back(thd);

		if(cfg.iCpuAff >= 0)
			printer::inst()->print_msg(L1, "Starting %s thread, affinity: %d.", cfg.bDoubleMode ? "double" : "single", (int)cfg.iCpuAff);
		else
			printer::inst()->print_msg(L1, "Starting %s thread, no affinity.", cfg.bDoubleMode ? "double" : "single");
	}

	iThreadCount = n;
	return pvThreads;
}

void minethd::switch_work(miner_work& pWork)
{
	// iConsumeCnt is a basic lock-like polling mechanism just in case we happen to push work
	// faster than threads can consume them. This should never happen in real life.
	// Pool cant physically send jobs faster than every 250ms or so due to net latency.

	while (iConsumeCnt.load(std::memory_order_seq_cst) < iThreadCount)
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

	oGlobalWork = pWork;
	iConsumeCnt.store(0, std::memory_order_seq_cst);
	iGlobalJobNo++;
}

void minethd::consume_work()
{
	memcpy(&oWork, &oGlobalWork, sizeof(miner_work));
	iJobNo++;
	iConsumeCnt++;
}

template<size_t N>
minethd::cn_hash_fun_multi minethd::func_multi_selector(bool bHaveAes, bool bNoPrefetch)
{
	static_assert(N >= 1, "number of threads must be >= 1" );

	static const cn_hash_fun_multi func_table[] = {
		Cryptonight_hash<N>::template hash<cryptonight_monero_v8, false, false>,
		Cryptonight_hash<N>::template hash<cryptonight_monero_v8, true, false>,
		Cryptonight_hash<N>::template hash<cryptonight_monero_v8, false, true>,
		Cryptonight_hash<N>::template hash<cryptonight_monero_v8, true, true>
	};

	std::bitset<2> digit;
	digit.set(0, !bHaveAes);
	digit.set(1, !bNoPrefetch);

	auto selected_function = func_table[ digit.to_ulong() ];

	return selected_function;
}

void minethd::pin_thd_affinity()
{
	// pin memory to NUMA node
	bindMemoryToNUMANode(affinity);

#if defined(__APPLE__)
	printer::inst()->print_msg(L1, "WARNING on MacOS thread affinity is only advisory.");
#endif
	thd_setaffinity(oWorkThd.native_handle(), affinity);
}

void minethd::work_main()
{
	multiway_work_main<1u>();
}

void minethd::double_work_main()
{
	multiway_work_main<2u>();
}

void minethd::penta_work_main()
{
	multiway_work_main<5u>();
}

template<size_t N>
void minethd::prep_multiway_work(uint8_t *bWorkBlob, uint32_t **piNonce)
{
	for (size_t i = 0; i < N; i++)
	{
		memcpy(bWorkBlob + oWork.iWorkSize * i, oWork.bWorkBlob, oWork.iWorkSize);
		if (i > 0)
			piNonce[i] = (uint32_t*)(bWorkBlob + oWork.iWorkSize * i + 39);
	}
}

template<uint32_t N>
void minethd::multiway_work_main()
{
	if(affinity >= 0) //-1 means no affinity
		pin_thd_affinity();

	std::unique_lock<std::mutex> lck(thd_aff_set);
	lck.release();
	std::this_thread::yield();

	cryptonight_ctx *ctx[MAX_N];
	uint64_t iCount = 0;
	uint64_t *piHashVal[MAX_N];
	uint32_t *piNonce[MAX_N];
	uint8_t bHashOut[MAX_N * 32];
	uint8_t bWorkBlob[sizeof(miner_work::bWorkBlob) * MAX_N];
	uint32_t iNonce;
	job_result res;

	for (size_t i = 0; i < N; i++)
	{
		ctx[i] = minethd_alloc_ctx();
		if(ctx[i] == nullptr)
		{
			printer::inst()->print_msg(L0, "ERROR: miner was not able to allocate memory.");
			for (int j = 0; j < i; j++)
				cryptonight_free_ctx(ctx[j]);
			exit(1);
		}
		piHashVal[i] = (uint64_t*)(bHashOut + 32 * i + 24);
		piNonce[i] = (i == 0) ? (uint32_t*)(bWorkBlob + 39) : nullptr;
	}

	if(!oWork.bStall)
		prep_multiway_work<N>(bWorkBlob, piNonce);

	iConsumeCnt++;

	// start with root algorithm and switch later if fork version is reached
	cn_hash_fun_multi hash_fun_multi = func_multi_selector<N>(::jconf::inst()->HaveHardwareAes(), bNoPrefetch);

	while (bQuit == 0)
	{
		if (oWork.bStall)
		{
			/*	We are stalled here because the executor didn't find a job for us yet,
			either because of network latency, or a socket problem. Since we are
			raison d'etre of this software it us sensible to just wait until we have something*/

			while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
				std::this_thread::sleep_for(std::chrono::milliseconds(100));

			consume_work();
			prep_multiway_work<N>(bWorkBlob, piNonce);
			continue;
		}

		constexpr uint32_t nonce_chunk = 4096;
		int64_t nonce_ctr = 0;

		assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));

		if(oWork.bNiceHash)
			iNonce = calc_nicehash_nonce(*piNonce[0], oWork.iResumeCnt);
		else
			iNonce = calc_start_nonce(oWork.iResumeCnt);

		hash_fun_multi = func_multi_selector<N>(::jconf::inst()->HaveHardwareAes(), bNoPrefetch);

		while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
		{
			if ((iCount++ & 0x7) == 0)  //Store stats every 8*N hashes
			{
				using namespace std::chrono;
				uint64_t iStamp = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();
				iHashCount.store(iCount * N, std::memory_order_relaxed);
				iTimestamp.store(iStamp, std::memory_order_relaxed);
			}

			for (size_t i = 0; i < N; i++)
				*piNonce[i] = iNonce++;

			hash_fun_multi(bWorkBlob, oWork.iWorkSize, bHashOut, ctx);

			for (size_t i = 0; i < N; i++)
			{
				if (*piHashVal[i] < oWork.iTarget)
				{
					executor::inst()->push_event(
                         ex_event(job_result(oWork.sJobID, iNonce - N + i, bHashOut + 32 * i, iThreadNo),
						oWork.iPoolId)
					);
				}
			}

			std::this_thread::yield();
		}

		consume_work();
		prep_multiway_work<N>(bWorkBlob, piNonce);
	}

	for (int i = 0; i < N; i++)
		cryptonight_free_ctx(ctx[i]);
}


