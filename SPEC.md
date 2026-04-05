# SPEC.md — libciphers

## Purpose

A Python library providing implementations of classical cipher algorithms for cryptographic puzzles, CTF challenges, and educational purposes. Supports both encryption and decryption operations for various classical cipher types.

## Scope

### Included
- **Shift Ciphers**: Caesar, ROT13, ROT-N, Atbash
- **Affine Ciphers**: Standard affine with a,b parameters
- **Polyalphabetic Ciphers**: Vigenère, Beaufort, Variant Beaufort, Autokey, Running Key, Porta, Quagmire variants
- **Grid Ciphers**: Polybius Square, Straddling Checkerboard
- **Transposition Ciphers**: Columnar, Rail Fence, Scytale, Route, Zigzag, Myszkowski
- **Digraph Ciphers**: Playfair, Four-Square, Three-Square
- **Fractionated Ciphers**: Bifid, Trifid
- **Hill Cipher**: 2x2 matrix encryption/decryption
- **Other Ciphers**: Gronsfeld, Gromark, Bazeries, XOR, Ragbaby, Cadenus, Cunningham, Slidefair
- **Enigma**: Simplified 3-rotor Enigma machine
- **Statistical Analysis**: Index of Coincidence, Chi-squared, N-gram scoring, Kasiski examination

### Not in Scope
- Modern ciphers (AES, RSA, etc.)
- Hash functions
- Public key cryptography

## Public API / Interface

### Core Functions
All functions accept string input and return string output. Functions preserve non-alphabetic characters unless otherwise specified.

| Function | Description |
|----------|-------------|
| `let2n(c)` | Convert letter to number (A=0, ..., Z=25) |
| `n2let(n)` | Convert number to letter (0=A, ..., 25=Z) |
| `clean_text(text)` | Remove non-alphabetic, uppercase |
| `keyed_alphabet(keyword)` | Generate keyed alphabet from keyword |

### Shift Ciphers
| Function | Signature | Description |
|----------|-----------|-------------|
| `caesar_encrypt(plaintext, shift)` | `(str, int) -> str` | Caesar encryption |
| `caesar_decrypt(ciphertext, shift)` | `(str, int) -> str` | Caesar decryption |
| `caesar_brute_force(ciphertext)` | `(str) -> list` | Try all 25 shifts |
| `atbash(text)` | `(str) -> str` | Atbash cipher |
| `rot13(text)` | `(str) -> str` | ROT13 cipher |
| `affine_encrypt(plaintext, a, b)` | `(str, int, int) -> str` | Affine encryption |
| `affine_decrypt(ciphertext, a, b)` | `(str, int, int) -> str` | Affine decryption |

### Polyalphabetic Ciphers
| Function | Signature | Description |
|----------|-----------|-------------|
| `vigenere_encrypt(plaintext, key)` | `(str, str) -> str` | Vigenère encryption |
| `vigenere_decrypt(ciphertext, key)` | `(str, str) -> str` | Vigenère decryption |
| `beaufort_encrypt(plaintext, key)` | `(str, str) -> str` | Beaufort encryption |
| `beaufort_decrypt(ciphertext, key)` | `(str, str) -> str` | Beaufort decryption |
| `autokey_encrypt(plaintext, seed)` | `(str, str) -> str` | Autokey encryption |
| `autokey_decrypt(ciphertext, seed)` | `(str, str) -> str` | Autokey decryption |
| `running_key_encrypt(plaintext, key)` | `(str, str) -> str` | Running key encryption |
| `running_key_decrypt(ciphertext, key)` | `(str, str) -> str` | Running key decryption |
| `porta_dec(ciphertext, key)` | `(str, str) -> str` | Porta cipher decryption |
| `gronsfeld_encrypt(plaintext, key)` | `(str, str) -> str` | Gronsfeld encryption |
| `gronsfeld_decrypt(ciphertext, key)` | `(str, str) -> str` | Gronsfeld decryption |

### Transposition Ciphers
| Function | Signature | Description |
|----------|-----------|-------------|
| `columnar_transpose_encrypt(plaintext, keyword)` | `(str, str) -> str` | Columnar encryption |
| `columnar_transpose_decrypt(ciphertext, keyword)` | `(str, str) -> str` | Columnar decryption |
| `rail_fence_encrypt(plaintext, rails)` | `(str, int) -> str` | Rail fence encryption |
| `rail_fence_decrypt(ciphertext, rails)` | `(str, int) -> str` | Rail fence decryption |
| `scytale_encrypt(plaintext, rods)` | `(str, int) -> str` | Scytale encryption |
| `scytale_decrypt(ciphertext, rods)` | `(str, int) -> str` | Scytale decryption |

### Digraph Ciphers
| Function | Signature | Description |
|----------|-----------|-------------|
| `playfair_encrypt(plaintext, keyword)` | `(str, str) -> str` | Playfair encryption |
| `playfair_decrypt(ciphertext, keyword)` | `(str, str) -> str` | Playfair decryption |
| `foursquare_encrypt(plaintext, key1, key2)` | `(str, str, str) -> str` | Four-Square encryption |
| `foursquare_decrypt(ciphertext, key1, key2)` | `(str, str, str) -> str` | Four-Square decryption |

### Fractionated Ciphers
| Function | Signature | Description |
|----------|-----------|-------------|
| `bifid_encrypt(plaintext, keyword, period)` | `(str, str, int) -> str` | Bifid encryption |
| `bifid_decrypt(ciphertext, keyword, period)` | `(str, str, int) -> str` | Bifid decryption |
| `trifid_encrypt(plaintext, keyword, period)` | `(str, str, int) -> str` | Trifid encryption |
| `trifid_decrypt(ciphertext, keyword, period)` | `(str, str, int) -> str` | Trifid decryption |

### Other Ciphers
| Function | Signature | Description |
|----------|-----------|-------------|
| `hill_encrypt(plaintext, key_matrix)` | `(str, list[list[int]]) -> str` | Hill encryption (2x2) |
| `hill_decrypt(ciphertext, key_matrix)` | `(str, list[list[int]]) -> str` | Hill decryption (2x2) |
| `polybius_encrypt(plaintext, square)` | `(str, str?) -> str` | Polybius square |
| `polybius_decrypt(numbers, square)` | `(str, str?) -> str` | Polybius decryption |
| `xor_cipher(text, key)` | `(str, str) -> str` | XOR-based cipher |
| `bazeries_decrypt(ciphertext, key)` | `(str, str) -> str` | Bazeries cipher |

### Statistical Functions
| Function | Signature | Description |
|----------|-----------|-------------|
| `index_of_coincidence(text)` | `(str) -> float` | Calculate IC |
| `chi_squared(text, freq)` | `(str, dict?) -> float` | Chi-squared statistic |
| `ngram_score(text, n)` | `(str, int) -> float` | N-gram frequency score |
| `kasiski_examination(ciphertext)` | `(str) -> list` | Find key length |
| `find_vigenere_key_length(ciphertext, max_len)` | `(str, int) -> list` | IC-based key length |

### Enigma
| Class | Description |
|-------|-------------|
| `Enigma(rotors, reflector, ring_settings, start_positions)` | Simplified 3-rotor Enigma |
| `Enigma.encrypt(plaintext)` | Enigma encryption |
| `Enigma.decrypt(ciphertext)` | Enigma decryption |

## Data Formats

- **Input**: Strings (plaintext/ciphertext), case-insensitive
- **Key**: String or integer parameters
- **Output**: String (ciphertext/plaintext)
- **Matrix**: 2x2 list of integers for Hill cipher

## Edge Cases

1. Empty input strings - return empty string
2. Non-alphabetic characters - preserved in output
3. Odd-length input for digraph ciphers - append padding character
4. Invalid affine multiplier (not coprime to 26) - return None
5. J/I substitution in Playfair - treat J as I
6. Key shorter than plaintext - key repeats cyclically
7. Invalid characters in key - ignored/skipped
8. Case sensitivity - output matches input case where applicable

## Performance & Constraints

- Pure Python implementation (no external dependencies)
- All operations O(n) where n = text length
- Memory: O(n) for all operations
- No rate limiting or concurrency handling required
