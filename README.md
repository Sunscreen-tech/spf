# Overview

This repository contains Sunscreen's secure processing framework (SPF), which allows users to run computations over encrypted data based specifically on our own variant of the torus fully homomorphic encryption scheme (TFHE).

Developer documentation is available [here](https://docs.sunscreen.tech/intro.html).

If you'd like to learn more about our motivation for this work, we recommend [this blog post](https://blog.sunscreen.tech/a-new-vision-for-tfhe-and-compilers/).

# Repository Navigation

This repository is composed of various components in individual crates.

## Underlying Mathematical Components

Crates `sunscreen_math`, `sunscreen_math_macros` and `sunscreen_tfhe` include the mathematical components used for the homomorphic encryption. This includes the algebraic structures, different ciphertext types, the computation algorithms (e.g. Fast Fourier Transformation) among other things.

## Multiplexer Circuits

Crate `mux_circuits` includes the MUX circuits for the required computation such as multiplying, adding and comparison.

## Processing Unit

Crate `parasol_runtime`, `parasol_cpu_macros` and `parasol_cpu` include the core SPF libraries (such as fluent) and implementation of the instructions in the Parasol ISA. This includes key generation, ciphertext conversion, instruction scheduling and execution among other things.

## Misc

Crate `parasol_concurrency` includes a few data structures such as spinlock and atomic refcell used by the SPF core. Directory `examples` includes crate `basic_add` as an example.

# Installation

While the contained `parasol_cpu` crate contains everything you need to *run* programs, to write them you'll need the Parasol-llvm compiler. You can get that [here](https://docs.sunscreen.tech/install.html).

* Download the tar file for your host architecture and OS.
* Run `tar xvzf parasol-compiler-<variant>.tar.gz`.
* Optionally an environment variable to the untarred location's contained bin directory.

# License

This is currently licensed under [APGLv3](https://www.gnu.org/licenses/agpl-3.0.html). If you require a different license, please [email us](mailto:hello@sunscreen.tech) and we'll see what we can do.

# Disclaimers

This code has *not* been audited. Use at your own risk.
