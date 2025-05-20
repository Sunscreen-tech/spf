# HPU
This repository contains Sunscreen's homomorphic processing unit (HPU), which is composed of various components in individual crates.

## Underlying Mathematical Components

Crates `sunscreen_math`, `sunscreen_math_macros` and `sunscreen_tfhe` include the mathematical components used for the homomorphic encryption. This includes the algebraic structures, different ciphertext types, the computation algorithms (e.g. Fast Fourier Transformation) among other things.

## Multiplexer Circuits

Crate `mux_circuits` includes the MUX circuits for the required computation such as multiplying, adding and comparison.

## Processing Unit

Crate `parasol_runtime`, `parasol_cpu_macros` and `parasol_cpu` include the core HPU libraries (such as fluent) and implementation of the instructions in the Parasol ISA. This includes key generation, ciphertext conversion, instruction scheduling and execution among other things.

## Misc

Crate `parasol_concurrency` includes a few data structures such as spinlock and atomic refcell used by the HPU core. Directory `examples` includes crate `basic_add` as an example.