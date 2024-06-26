.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo: 				
	cmp #1, r15
	jeq 1f

	;Address of __sm_foo_public_end
	mov #0x6c3c, r15

	br r15
	jmp __sm_foo_public_end
1:
	mov #0xdead, r15
	jmp __sm_foo_public_end

__sm_foo_public_end:

    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
    .word 0x0
__sm_foo_secret_end:
