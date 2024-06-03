#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>

DECLARE_SM(basic_enclave, 0x1234);

int SM_ENTRY(basic_enclave) basic_function(int arg)
{
	if (arg < 0)
	{
		pr_info("This branch will take the exit stub");
		return 0;
	}
	return 1;
}

int main()
{
    msp430_io_init();

    pr_info("enabling basic_enclave SM..");
    sancus_enable(&basic_enclave);
    pr_sm_info(&basic_enclave);

	basic_function(-5);
	basic_function(10);

    pr_info("all done!");
    EXIT();
}
