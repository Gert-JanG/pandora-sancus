#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>

DECLARE_SM(sm_loader, 0x1234);

/* ======== ENCLAVE FUNCTION ======== */

int SM_ENTRY(sm_loader) sm_loader_load(struct SancusModule *scm)
{
	size_t pstart  = (size_t)scm->public_start;
    size_t pend    = (size_t)scm->public_end;
    size_t pcstart = (size_t)scm->public_start;
    size_t pcend   = (size_t)scm->public_end;
    size_t i;
    int ret;

    // check boundaries
    if (pend < pstart || pcend < pcstart)
        return 0;

    // check sizes
    if ((pend - pstart) != (pcend - pcstart))
        return 0;
	
	//...
}

int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&sm_loader);
	
	sm_loader_load(&sm_loader);
	

	return 0;
}

