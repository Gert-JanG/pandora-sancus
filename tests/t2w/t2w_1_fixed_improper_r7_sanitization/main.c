#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>


DECLARE_SM(basic_enclave, 0x1234);

/* ======== ENCLAVE FUNCTION ======== */

char SM_ENTRY(basic_enclave) enter_encl()
{
	return 'a';
}

int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&basic_enclave);

	char t = enter_encl();
	
	pr_info1("enclave returned %c", t);
	return 0;
}

