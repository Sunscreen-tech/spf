	.text
	.file	"cardio.c"
	.globl	cardio                          ; -- Begin function cardio
	.type	cardio,@function
cardio:                                 ; @cardio
; %bb.0:                                ; %entry
	trunc	x1, x10, 8, 32
	ldi	x5, 1, 32
	shr	x5, x1, x5
	trunc	x5, x5, 1, 8
	zext	x5, x5, 8, 1
	ldi	x6, 2, 32
	shr	x6, x1, x6
	trunc	x6, x6, 1, 8
	zext	x6, x6, 8, 1
	add	x5, x6, x5
	ldi	x6, 3, 32
	shr	x6, x1, x6
	trunc	x6, x6, 1, 8
	zext	x6, x6, 8, 1
	add	x5, x5, x6
	trunc	x6, x11, 8, 32
	ldi	x7, 60, 8
	gt	x7, x6, x7
	trunc	x1, x1, 1, 8
	not	x1, x1
	and	x7, x7, x1
	zext	x7, x7, 8, 1
	add	x5, x5, x7
	ldi	x7, 50, 8
	gt	x6, x6, x7
	trunc	x7, x10, 1, 32
	and	x6, x7, x6
	zext	x6, x6, 8, 1
	add	x5, x5, x6
	trunc	x6, x12, 8, 32
	ldi	x10, 40, 8
	lt	x6, x6, x10
	zext	x6, x6, 8, 1
	add	x5, x5, x6
	trunc	x6, x14, 8, 32
	ldi	x10, -90, 8
	add	x6, x6, x10
	trunc	x10, x13, 8, 32
	lt	x6, x6, x10
	zext	x6, x6, 8, 1
	add	x5, x5, x6
	trunc	x6, x15, 8, 32
	ldi	x10, 30, 8
	lt	x6, x6, x10
	zext	x6, x6, 8, 1
	add	x5, x5, x6
	trunc	x6, x16, 8, 32
	ldi	x10, 3, 8
	gt	x10, x6, x10
	and	x7, x7, x10
	zext	x7, x7, 8, 1
	add	x5, x5, x7
	ldi	x7, 2, 8
	gt	x6, x6, x7
	and	x1, x6, x1
	zext	x1, x1, 8, 1
	add	x1, x5, x1
	zext	x10, x1, 32, 8
	ret
.Lfunc_end0:
	.size	cardio, .Lfunc_end0-cardio
                                        ; -- End function
	.ident	"clang version 18.1.6 (git@github.com:Sunscreen-tech/tfhe-llvm.git 33880b83e9093d3e2a6dc3f95dd6b33a73905f76)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
