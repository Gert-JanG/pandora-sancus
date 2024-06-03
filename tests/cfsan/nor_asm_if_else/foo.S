.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo:
	push r15
	mov #99, r12
	pop r15
	;if r11 is zero, increment argument
	cmp #0, r11
	jeq 1f
	mov #0xcafe, r10
	;else if arg >= 10, decrement argument
	cmp #10, r15
	jge 2f	
	;else add 420 to argument
	add #420, r15
	jmp __sm_foo_public_end
1:
	;increment argument with 1
	inc r15
	jmp __sm_foo_public_end

2:
	dec r15
	jmp __sm_foo_public_end
	
__sm_foo_public_end:

    ; NOTE: we do the ret _outside_ of the enclave, as the stack pointer is
    ; untrusted and could be poisoned to point _inside_ the enclave..
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
