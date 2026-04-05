# libciphers

A Python library providing implementations of classical cipher algorithms for cryptographic puzzles, CTF challenges, and educational purposes.

[![PyPI](https://img.shields.io/pypi/v/libciphers.svg)](https://pypi.org/project/libciphers/)
[![Python](https://img.shields.io/pypi/pyversions/libciphers.svg)](https://pypi.org/project/libciphers/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Install

```bash
pip install libciphers
```

## Usage

```python
from libciphers import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt

# Caesar cipher
plaintext = "HELLO"
encrypted = caesar_encrypt(plaintext, 5)
decrypted = caesar_decrypt(encrypted, 5)
print(f"Caesar: {encrypted} -> {decrypted}")  # MJQQT -> HELLO

# Vigenère cipher
encrypted = vigenere_encrypt("HELLO", "KEY")
decrypted = vigenere_decrypt(encrypted, "KEY")
print(f"Vigenère: {encrypted} -> {decrypted}")  # RIJVQ -> HELLO
```

## Supported Ciphers

### Shift Ciphers
- Caesar (with brute force)
- ROT13, ROT-N
- Atbash
- Affine

### Polyalphabetic Ciphers
- Vigenère
- Beaufort
- Variant Beaufort
- Autokey
- Running Key
- Porta
- Gronsfeld
- Quagmire variants

### Transposition Ciphers
- Columnar
- Rail Fence
- Scytale
- Route
- Zigzag

### Digraph Ciphers
- Playfair
- Four-Square
- Three-Square

### Fractionated Ciphers
- Bifid
- Trifid

### Other Ciphers
- Hill (2x2)
- Polybius Square
- Bazeries
- XOR
- Enigma (3-rotor)

### Statistical Analysis
- Index of Coincidence
- Chi-squared
- N-gram scoring
- Kasiski examination

## Development

```bash
git clone https://github.com/daedalus/libciphers.git
cd libciphers
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```
