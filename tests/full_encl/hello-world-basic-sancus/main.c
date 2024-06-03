#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>

void exit_success(void);

/* ======== HELLO WORLD SM ======== */

DECLARE_SM(hello, 0x1234);

void SM_ENTRY(hello) hello_enclave(void)
{
    pr_info("Hello Enclave!");
}

void SM_ENTRY(hello) disable_enclave(void)
{
    //Pass the continuation to indicate where to continue
    sancus_disable(exit_success);
}

/* ======== UNTRUSTED CONTEXT ======== */
int main()
{
    //Setup UART and stuff
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&hello);

    hello_enclave();
    pr_info1("Untrust id is: %d \n", sancus_get_self_id());
    pr_info1("Trusted id is: %d \n", sancus_get_id(hello_enclave));
    disable_enclave();
}

void exit_success(void)
{
    //Make sure the enclave id is just 0 (enclave is destroyed)
    ASSERT(!sancus_get_id(hello_enclave));

    //Shut down the simulation
    FINISH();
}

