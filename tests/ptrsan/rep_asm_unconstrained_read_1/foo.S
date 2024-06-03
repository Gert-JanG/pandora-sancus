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
	nop
	mov #10, r14
	add #100, r14

    ret

__sm_foo_public_end:


.section ".sm.foo.data"
__sm_foo_secret_start:
    .word 0x0
__sm_foo_secret_end:
