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
	cmp #0x6c0c, r15
	jl end

	;constrain a path in symbolic execution to r15 containing an address above 
	;the enclave base address
	cmp #0x6c1a, r15
	jge end

	nop
	nop
	mov r13, @r15
	jmp __sm_foo_public_end

__sm_foo_public_end:
end:

    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
