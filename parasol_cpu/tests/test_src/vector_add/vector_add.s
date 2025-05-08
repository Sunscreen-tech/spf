	.text
	.file	"vector_add.c"
	.globl	vector_add                      ; -- Begin function vector_add
	.type	vector_add,@function
vector_add:                             ; @vector_add
; %bb.0:                                ; %entry
	ldr	x1, x10, 8
	ldr	x5, x11, 8
	add	x1, x5, x1
	str	x12, x1, 8
	ldi	x1, 1, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ldi	x1, 2, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ldi	x1, 3, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ldi	x1, 4, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ldi	x1, 5, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ldi	x1, 6, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ldi	x1, 7, 32
	add	x5, x10, x1
	ldr	x5, x5, 8
	add	x6, x11, x1
	ldr	x6, x6, 8
	add	x5, x6, x5
	add	x1, x12, x1
	str	x1, x5, 8
	ret
.Lfunc_end0:
	.size	vector_add, .Lfunc_end0-vector_add
                                        ; -- End function
	.ident	"clang version 18.1.6 (git@github.com:Sunscreen-tech/tfhe-llvm.git 33880b83e9093d3e2a6dc3f95dd6b33a73905f76)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
