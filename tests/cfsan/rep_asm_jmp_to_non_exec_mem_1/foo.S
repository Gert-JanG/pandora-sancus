.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo
.global next

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo:
	br #0x0


__sm_foo_public_end:
    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
