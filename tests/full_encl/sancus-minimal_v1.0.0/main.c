#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>

DECLARE_SM(foo, 0x1234);

int SM_ENTRY(foo) foo_c_fct(int a)
{
	return a;
}

int main()
{
    msp430_io_init();

    pr_info("enabling foo SM..");
    sancus_enable(&foo);
    pr_sm_info(&foo);

    pr_info("entering foo..");
    int res = foo_c_fct(1);
    printf("foo_c_fct(1)=%#x\n", res);

    pr_info("all done!");
    EXIT();
}
