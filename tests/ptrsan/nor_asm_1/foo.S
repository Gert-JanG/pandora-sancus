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
	mov r1, r11
	;The end address of the enclave data range
	mov #0x239, r1
	push r11
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
	.space 64
__sm_foo_secret_end:
