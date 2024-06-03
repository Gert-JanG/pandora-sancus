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
	call plus
	jmp 1f

plus:
	add r14, r15
	ret
	
__sm_foo_public_end:
	nop
	nop
1:
    ret



.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
