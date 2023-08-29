# ECDSA_fhe_int

This repository contains a straightforward Fully Homomorphic Encryption implementation of ECDSA, using homomorphic integer operations. It works similarly to our [boolean implementation](https://github.com/JoseSK999/ECDSA_fhe/tree/main), but takes advantage of the arithmetic operations provided by tfhe-rs, simplifying the overall codebase.

As of now, we are using a specific git branch of tfhe-rs that enables us to perform modular reduction with large numbers. This will be updated in the future.
