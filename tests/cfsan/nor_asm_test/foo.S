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
	cmp #0x0, r6
	jz __sm_foo_public_end
	cmp #0x0, r7
	jz __sm_foo_public_end
	cmp #0x0, r8
	jz 1f
	nop
	nop
	br #__sm_foo_public_end

1:
	mov #0x12, r8
	nop
	jmp __sm_foo_public_end

__sm_foo_public_end:
	nop
	nop
    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret



.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
