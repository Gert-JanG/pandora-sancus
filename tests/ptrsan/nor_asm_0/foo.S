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
	jmp __sm_foo_public_end

__sm_foo_public_end:
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
