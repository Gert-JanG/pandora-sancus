#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>
#include <alloca.h>

#define __OUTSIDE_SM( p, sm )                                                  \
    ( ((void*) p < (void*) &__PS(sm)) || ((void*) p >= (void*) &__PE(sm)) ) && \
    ( ((void*) p < (void*) &__SS(sm)) || ((void*) p >= (void*) &__SE(sm)) )

#define sancus_is_outside_sm_vulnerable(sm, p, len) \
    ( __OUTSIDE_SM(p, sm) && __OUTSIDE_SM((p+len-1), sm) )

DECLARE_SM(basic_enclave, 0x1234);


/* ============= ENCLAVE ============= */

void SM_ENTRY(basic_enclave) copy_data_from_buffer(int *buffer, int length)
{
	//vulnerable function
	if (!sancus_is_outside_sm_vulnerable(basic_enclave, buffer, length*2)) return;
	
	for (int i = 0; i < length; i++) 
	{
		//set some nops just to immediately indicate this point in the disassembly 
		asm("nop");
		asm("nop");
		asm("nop");
		//access the data
   		int result = buffer[i];
	}
	return;
}

/* ======== UNTRUSTED CONTEXT ======== */
int main()
{
    //Setup UART etc.
    msp430_io_init();

	unsigned long address = 0x2fc;
	int *buffer = (int *)address;
	size_t len = 0x500; 

	pr_info("Enabling protections");
    //Initialize enclave
    sancus_enable(&basic_enclave);
    copy_data_from_buffer(buffer, len);

	return 0;
}

