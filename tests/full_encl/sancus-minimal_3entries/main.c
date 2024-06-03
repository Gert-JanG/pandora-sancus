#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>


DECLARE_SM(basic_enclave, 0x1234);

/* ======== ENCLAVE FUNCTION ======== */

int SM_ENTRY(basic_enclave) plus_one(int parameter)
{
	return parameter + 1;	
}

int SM_ENTRY(basic_enclave) plus_two(int parameter)
{
	return parameter + 2;
}

int SM_ENTRY(basic_enclave) plus_three(int parameter)
{
	return parameter + 3;
}

/* ======== UNTRUSTED CONTEXT ======== */
int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&basic_enclave);

    int enclave_result = plus_one(1);
    int enclave_result2 = plus_two(1);
	enclave_result += enclave_result2;
	return(enclave_result);
}

