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
	; We do not explicitly jump to the end of the enclave here, as this should be reported by the
	; CFSan plugin. This bb crosses the boundary of the enclave.

__sm_foo_public_end:

    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
