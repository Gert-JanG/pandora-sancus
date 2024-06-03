#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>


DECLARE_SM(basic_enclave, 0x1234);

/* ======== ENCLAVE FUNCTION ======== */

char SM_ENTRY(basic_enclave) enter_encl()
{
	//Enclave reentry not supported so paths in this branch will end here
	pr_info("This is the basic_enclave");
	return 'a';
}

const char* SM_ENTRY(basic_enclave) another_entry(int one)
{
	asm("nop");
	return "Enclave";
}

int SM_FUNC(basic_enclave) plus_one(int parameter)
{
	return parameter + 1;	
}

int SM_FUNC(basic_enclave) do_something_cool(int one, int two, int three, int four, int five) 
{
	int res = one + two + three + four + five;
	return res;

}

/* ======== UNTRUSTED CONTEXT ======== */
int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&basic_enclave);

	return 0;
}

