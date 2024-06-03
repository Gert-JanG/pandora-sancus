#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>


DECLARE_SM(basic_enclave, 0x1234);
int SM_DATA(basic_enclave) fib_number = 4;

/* ======== ENCLAVE FUNCTION ======== */

int SM_FUNC(basic_enclave) fib(int n)
{
		int a = 0;
		int b = 1;
		int t;
		for (int i = 2; i <= n; i++)
		{
				t = a + b;
				a = b;
				b = t;
		}
		return b;
}

int SM_ENTRY(basic_enclave) fibonacci()
{
		int r = 0;
		for (int i = 0; i < fib_number; i++)
		{
				r += fib(i);
		}
		return(r);
}

/* ======== UNTRUSTED CONTEXT ======== */
int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&basic_enclave);

    int enclave_result = fibonacci();
	return(enclave_result);
}

