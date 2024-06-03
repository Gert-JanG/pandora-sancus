#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>


DECLARE_SM(basic_enclave, 0x1234);

/* ======== ENCLAVE FUNCTION ======== */

int SM_ENTRY(basic_enclave) fib(int n)
{
	if (n < 0) return -1;
	else if (n == 0 || n == 1) return 1;
	else return fib(n-1) + fib(n-2);

}

/* ======== UNTRUSTED CONTEXT ======== */
int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&basic_enclave);

    int enclave_result = fib(9);
	return(enclave_result);
}

