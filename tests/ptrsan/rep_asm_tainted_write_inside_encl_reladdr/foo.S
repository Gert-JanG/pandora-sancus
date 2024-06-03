.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo
.global end

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo:
	;constrain a path in symbolic execution to r15 containing an address above 
	;the enclave base address
	cmp __sm_foo_secret_start, r15
	jl end

	;constrain a path in symbolic execution to r15 containing an address above 
	;the enclave base address
	mov __sm_foo_secret_start, r14
	add #10, r14
	cmp r14, r15
	jge end

	mov r13, @r15
	jmp __sm_foo_public_end

__sm_foo_public_end:
end:

    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
    .word 0x1234
	.space 64
	.word 0x5678
__sm_foo_secret_end:

