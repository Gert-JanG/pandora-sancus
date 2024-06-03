#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>


DECLARE_SM(basic_enclave, 0x1234);

/* ============= ENCLAVE ============= */
int SM_DATA(basic_enclave) priv_data = 3;

int SM_FUNC(basic_enclave) set_priv_data(int number)
{
	if (number > 0) {
		priv_data = number;
	} else {
		pr_info("Not possible to set priv_data lower than 0");	
		//no path in the validation will reach here as reentry is not yet supported
		return -1;
	}
	return 0;
}

int SM_ENTRY(basic_enclave) do_loop(int *buffer, size_t length)
{
	int result = priv_data;
	for (size_t i = 0; i < length; i++) {
			result +=  buffer[i];
	}
	return result;
}

const char* SM_ENTRY(basic_enclave) set_number(int amount)
{
	int res = set_priv_data(amount);
	if (res >= 0) {return "Number set";}
	else {return "Number not set";}
	
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
	const char* result = set_number(5);
	pr_info1("%s\n", result);
    do_loop(buffer, len);

	return 0;
}

