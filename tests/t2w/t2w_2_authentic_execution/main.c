#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>
#include <alloca.h>
#include "reactive_stubs_support.h"

DECLARE_SM(basic_enclave, 0x1234);

/* ======== ENCLAVE FUNCTION ======== */


#define AD_SIZE 2
#define SM_NUM_INPUTS 100
char SM_DATA(basic_enclave) __sm_num_inputs;
IoKey SM_DATA(basic_enclave) __sm_io_keys[SM_NUM_INPUTS];
InputCallback SM_DATA(basic_enclave) __sm_input_callbacks[SM_NUM_INPUTS];


void SM_ENTRY(basic_enclave) __sm_handle_input(uint16_t conn_id, 
				const void* payload, size_t len)
{
    if (conn_id >= SM_NUM_INPUTS)
        return;

    const size_t data_len = len - AD_SIZE - SANCUS_TAG_SIZE;
    const uint8_t* cipher = (uint8_t*)payload + AD_SIZE;
    const uint8_t* tag = cipher + data_len;

    // TODO check for stack overflow!
    uint8_t* input_buffer = alloca(data_len);
    if (sancus_unwrap_with_key(__sm_io_keys[conn_id], payload, AD_SIZE,
                               cipher, data_len, tag, input_buffer))
	{
        //__sm_input_callbacks[conn_id](input_buffer, data_len);
		return;
	}
}

int main()
{
    //Setup UART etc.
    msp430_io_init();

    //Initialize enclave
    sancus_enable(&basic_enclave);
	
	return 0;
}

