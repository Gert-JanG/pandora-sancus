.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo:
    nop
	nop
	mov #0x1, r15
	mov #0x2, r14

__sm_foo_public_end:
	nop
	nop
	jmp 1f
    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

1:
	nop
	ret


.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
