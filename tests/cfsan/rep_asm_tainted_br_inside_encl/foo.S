.global __sm_foo_public_start
.global __sm_foo_public_end
.global __sm_foo_secret_start
.global __sm_foo_secret_end
.global enter_foo
.global end

.section ".sm.foo.text", "wax"
.align 2
__sm_foo_public_start:
enter_foo:
	cmp #0x6c1a, r15
	jl end

	cmp #0x6c1e, r15
	jge end

	br r15
	; A small 'nop-sledge' to which we can constrain such that our symbex does not 
	; simulate inside the enclave indefinitely
	nop ;Address 0x6c1a
	nop 
	nop ;Address 0x6c1e
	nop
	jmp __sm_foo_public_end

__sm_foo_public_end:
end:
    ret

.section ".sm.foo.data"
__sm_foo_secret_start:
__sm_foo_secret_end:
