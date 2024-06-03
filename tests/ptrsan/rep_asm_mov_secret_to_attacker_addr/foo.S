.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo:
	mov #0x1233, r15
	;Write secret value to attacker tainted location
	mov #__sm_foo_secret_start, @r13	

	call #plusOne
	pop r1
	jmp __sm_foo_public_end

plusOne:
	add #1, r15
	ret
	
__sm_foo_public_end:
    ret


.section ".sm.foo.data"
__sm_foo_secret_start:
	.word 0x1234
	.space 64
__sm_foo_secret_end:
