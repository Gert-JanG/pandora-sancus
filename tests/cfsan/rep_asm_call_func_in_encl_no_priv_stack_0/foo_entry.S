.global __sm_foo_entry
.global foo_exit_trampoline
.global enter_foo
.global foo_c_fct

/* PROTECTED ENCLAVE CODE */
.section ".sm.foo.text", "wax"
.align 2
__sm_foo_entry:
enter_foo:
    mov #10, r14
    mov #0xdead, r15

	;Deliberately insecure with no private callstack
    call #foo_c_fct

    br #foo_exit_trampoline

/* UNPROTECTED CODE OUTSIDE ENCLAVE */
.text
foo_exit_trampoline:
    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

