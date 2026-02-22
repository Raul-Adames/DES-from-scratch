# DES From Scratch (Python)

Educational implementation of **DES (Data Encryption Standard)** written from scratch in Python.
It follows the structure described in *Cryptography and Network Security: Principles and Practice*.

All standard tables (S-Boxes, PC-1/PC-2, permutations, etc.) were taken from the textbook and included as constants in separate modules.

> Note: DES is considered obsolete/insecure today. This project is for learning purposes.

## Features
- Key schedule: PC-1, per-round left shifts, PC-2
- DES Feistel network: IP, 16 rounds, final swap, FP
- Text API: encrypt/decrypt UTF-8 strings in 8-byte blocks with PKCS#7-style padding

## Run
```bash
python main.py
```