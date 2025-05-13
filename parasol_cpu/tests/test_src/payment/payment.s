	.text
	.file	"payment.c"
	.globl	payment                         ; -- Begin function payment
	.type	payment,@function
payment:                                ; @payment
; %bb.0:                                ; %entry
	ldr	x1, x11, 32
	gt	x5, x1, x10
	ldi	x6, 0, 32
	cmux	x5, x5, x10, x6
	sub	x1, x1, x5
	str	x11, x1, 32
	ret
.Lfunc_end0:
	.size	payment, .Lfunc_end0-payment
                                        ; -- End function
	.ident	"clang version 18.1.6 (git@github.com:Sunscreen-tech/tfhe-llvm.git ae6064c11e37e7ab25a01915fcc73d4afe657f98)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
