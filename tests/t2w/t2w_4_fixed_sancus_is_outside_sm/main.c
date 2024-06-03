#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>
#include <alloca.h>

DECLARE_SM(basic_enclave, 0x1234);


/* ============= ENCLAVE ============= */

void SM_ENTRY(basic_enclave) copy_data_from_buffer(int *buffer, int length)
{
	//length*2 as size of integer is 2 bytes
	if (!sancus_is_outside_sm(basic_enclave, buffer, length*2)) return;
	
	for (int i = 0; i < length; i++)
	{
		asm("nop");
		asm("nop");
		asm("nop");
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

