#include <miner.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "rfv2/rfv2.h"

int scanhash_rfv2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);
	void *rambox;
	int ret = 0;

	if (opt_benchmark)
		Htarg = ptarget[7] = 0x1ffffff;

	//printf("thd%d work=%p htarg=%08x ptarg7=%08x first_nonce=%08x max_nonce=%08x hashes_done=%Lu\n",
	//       thr_id, work, Htarg, ptarget[7], first_nonce, max_nonce, (unsigned long)*hashes_done);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	rambox = malloc(RFV2_RAMBOX_SIZE * 8);
	if (rambox == NULL)
		goto out;

	rfv2_raminit(rambox);
	// pre-compute the hash state based on the constant part of the header

	do {
		be32enc(&endiandata[19], nonce);
		rfv2_hash(hash, endiandata, 80, rambox, NULL);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			applog_hex((void *) hash, 32); 
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			ret = 1;
			goto out;
		}
	next:
		nonce++;
	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
out:
	free(rambox);
	return ret;
}