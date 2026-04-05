#!/usr/bin/env python3
"""
Comprehensive Classical Cipher Algorithms Library
Merged from ciphers1.py, ciphers2.py, ciphers3.py
"""

__version__ = "0.1.0"

import itertools
import math
import string
from collections import Counter

A = string.ascii_uppercase

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def let2n(c):
    """Letter to number (A=0, B=1, ..., Z=25)"""
    return ord(c.upper()) - 65 if c.upper() in A else -1


def n2let(n):
    """Number to letter (0=A, 1=B, ..., 25=Z)"""
    return chr((n % 26) + 65)


def clean_text(text):
    """Remove non-alphabetic characters and uppercase."""
    return "".join(c.upper() for c in text if c in A)


def clean(text):
    """Remove non-alphabetic characters (alias)"""
    return "".join(c.upper() for c in text if c.upper() in A)


def text_to_numbers(text):
    """Convert text to list of numbers."""
    return [let2n(c) for c in clean_text(text)]


def numbers_to_text(numbers):
    """Convert list of numbers to text."""
    return "".join(n2let(n) for n in numbers)


def keyed_alphabet(keyword):
    """Create alphabet from keyword"""
    seen, result = set(), []
    for c in keyword.upper():
        if c in A and c not in seen:
            result.append(c)
            seen.add(c)
    for c in A:
        if c not in seen:
            result.append(c)
    return "".join(result)


def make_polybius(key):
    """Create Polybius square"""
    seen, sq = set(), []
    for c in key + A:
        if c != "J" and c not in seen:
            sq.append(c)
            seen.add(c)
    return sq


# ============================================================================
# SUBSTITUTION CIPHERS
# ============================================================================


def caesar_encrypt(plaintext, shift):
    """Caesar cipher encryption: C = (P + shift) mod 26"""
    plaintext = clean_text(plaintext)
    return "".join(n2let(let2n(c) + shift) for c in plaintext)


def caesar_decrypt(ciphertext, shift):
    """Caesar cipher decryption: P = (C - shift) mod 26"""
    ciphertext = clean_text(ciphertext)
    return "".join(n2let(let2n(c) - shift) for c in ciphertext)


def caesar_brute_force(ciphertext):
    """Try all 25 Caesar shifts."""
    return [caesar_decrypt(ciphertext, i) for i in range(26)]


def atbash(text):
    """Atbash cipher - letter reversal (A↔Z, B↔Y, etc.)"""
    result = []
    for c in text.upper():
        if c in A:
            result.append(n2let(25 - let2n(c)))
        else:
            result.append(c)
    return "".join(result)


def rot13(cipher):
    """ROT13 cipher"""
    return caesar_decrypt(cipher, 13)


def rot_n(cipher, n):
    """Generic ROT cipher with any n"""
    return caesar_decrypt(cipher, n)


def affine_encrypt(plaintext, a, b):
    """Affine cipher encryption: C = (a*P + b) mod 26"""
    plaintext = clean_text(plaintext)
    result = []
    for c in plaintext:
        p = let2n(c)
        c_val = (a * p + b) % 26
        result.append(n2let(c_val))
    return "".join(result)


def affine_decrypt(ciphertext, a, b):
    """Affine cipher decryption: P = a^-1 * (C - b) mod 26"""
    ciphertext = clean_text(ciphertext)
    a_inv = pow(a, -1, 26)
    return "".join(n2let((a_inv * (let2n(c) - b)) % 26) for c in ciphertext if c in A)


def affine_brute_force(ciphertext):
    """Try all valid Affine key pairs."""
    results = []
    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 21, 23, 25]
    for a in valid_a:
        for b in range(26):
            decrypted = affine_decrypt(ciphertext, a, b)
            if decrypted:
                results.append((a, b, decrypted))
    return results


def simple_substitution_decrypt(cipher: str, mapping: dict) -> str:
    """Simple substitution with given letter mapping"""
    result = ""
    for c in cipher:
        if c.isalpha():
            upper = c.isupper()
            mapped = mapping.get(c.upper(), c)
            result += mapped.upper() if upper else mapped.lower()
        else:
            result += c
    return result


def generate_playfair_matrix(key: str) -> list:
    """Generate Playfair cipher matrix"""
    key = key.upper().replace("J", "I")
    matrix = []
    seen = set()
    for c in key:
        if c not in seen and c.isalpha():
            seen.add(c)
            matrix.append(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen:
            matrix.append(c)
    return [matrix[i * 5 : (i + 1) * 5] for i in range(5)]


# ============================================================================
# POLYALPHABETIC CIPHERS
# ============================================================================


def vigenere_encrypt(plaintext, key):
    """Vigenère encryption: C[i] = (P[i] + K[i]) mod 26"""
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    return "".join(
        n2let(let2n(c) + let2n(key[i % len(key)])) for i, c in enumerate(plaintext)
    )


def vigenere_decrypt(ciphertext, key):
    """Vigenère decryption: P[i] = (C[i] - K[i]) mod 26"""
    return "".join(
        n2let((let2n(c) - let2n(key[i % len(key)])) % 26)
        for i, c in enumerate(ciphertext)
        if c in A
    )


def vigenere_dec_a1(cipher: str, key: str) -> str:
    """Vigenère with A=1 encoding"""
    result = ""
    key_repeated = (key * ((len(cipher) // len(key)) + 1))[: len(cipher)]
    for i, c in enumerate(cipher):
        if c.isalpha():
            base = ord("A")
            cipher_idx = ord(c) - base
            key_idx = ord(key_repeated[i].upper()) - base + 1
            plain_idx = (cipher_idx - key_idx) % 26
            result += chr(plain_idx + base)
        else:
            result += c
    return result


def vigenere_dec_pos(ct, key):
    """Vigenère with position offset (decryption)"""
    return "".join(
        n2let((let2n(c) - let2n(key[i % len(key)]) - i) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def vigenere_enc_pos(ct, key):
    """Vigenère with position offset (encryption)"""
    return "".join(
        n2let((let2n(c) + let2n(key[i % len(key)]) + i) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def vigenere_dec_cumulative(ct, key):
    """Vigenère with cumulative key (decryption)"""
    total = 0
    result = []
    for i, c in enumerate(ct):
        if c in A:
            total = (total + let2n(key[i % len(key)])) % 26
            result.append(n2let((let2n(c) - total) % 26))
        else:
            result.append(c)
    return "".join(result)


def vigenere_enc_cumulative(ct, key):
    """Vigenère with cumulative key (encryption)"""
    total = 0
    result = []
    for i, c in enumerate(ct):
        if c in A:
            total = (total + let2n(key[i % len(key)])) % 26
            result.append(n2let((let2n(c) + total) % 26))
        else:
            result.append(c)
    return "".join(result)


def beaufort_encrypt(plaintext, key):
    """Beaufort cipher encryption: C[i] = (K[i] - P[i]) mod 26"""
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    return "".join(
        n2let(let2n(key[i % len(key)]) - let2n(c)) for i, c in enumerate(plaintext)
    )


def beaufort_decrypt(ciphertext, key):
    """Beaufort cipher decryption (self-inverse)"""
    return "".join(
        n2let((let2n(key[i % len(key)]) - let2n(c)) % 26)
        for i, c in enumerate(ciphertext)
        if c in A
    )


def variant_beaufort_encrypt(plaintext, key):
    """Variant Beaufort cipher (same as Vigenère encryption)"""
    return vigenere_encrypt(plaintext, key)


def variant_beaufort_dec(ct, key):
    """Variant Beaufort cipher decryption: P[i] = (K[i] - C[i]) mod 26"""
    return "".join(
        n2let((let2n(c) + let2n(key[i % len(key)])) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def porta_dec(ct, key):
    """Porta cipher decryption"""
    porta_table = {
        "A": "NOPQRSTUVWXYZABCDEFGHIJKLM",
        "B": "OPQRSTUVWXYZNBCDEFGHIJKLMA",
        "C": "PQRSTUVWXYZABCDEFGHIJKLMNO",
        "D": "QRSTUVWXYZNBCDEFGHIJKLMAO",
        "E": "RSTUVWXYZABCDEFGHIJKLMNOP",
        "F": "STUVWXYZNBCDEFGHIJKLMAOP",
        "G": "TUVWXYZABCDEFGHIJKLMNOPQR",
        "H": "UVWXYZNBCDEFGHIJKLMAOPQS",
        "I": "VWXYZABCDEFGHIJKLMNOPQRST",
        "J": "WXYZNBCDEFGHIJKLMAOPQRSTU",
        "K": "XYZABCDEFGHIJKLMNOPQRSTUV",
        "L": "YZNBCDEFGHIJKLMAOPQRSTUVW",
        "M": "ZABCDEFGHIJKLMNOPQRSTUVWX",
        "N": "ABCDEFGHIJKLMNOPQRSTUVWXY",
        "O": "BCDEFGHIJKLMAOPQRSTUVWXYZ",
        "P": "CDEFGHIJKLMNOPQRSTUVWXYZAB",
        "Q": "DEFGHIJKLMAOPQRSTUVWXYZABC",
        "R": "EFGHIJKLMNOPQRSTUVWXYZABCD",
        "S": "FGHIJKLMAOPQRSTUVWXYZABCDE",
        "T": "GHIJKLMNOPQRSTUVWXYZABCDEF",
        "U": "HIJKLMAOPQRSTUVWXYZABCDEFG",
        "V": "IJKLMNOPQRSTUVWXYZABCDEFGH",
        "W": "JKLMAOPQRSTUVWXYZABCDEFGHI",
        "X": "KLMNOPQRSTUVWXYZABCDEFGHIJ",
        "Y": "LMNOPQRSTUVWXYZABCDEFGHIJK",
        "Z": "MNOPQRSTUVWXYZABCDEFGHIJKL",
    }
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = key[i % len(key)]
            result.append(porta_table[k][let2n(c)])
        else:
            result.append(c)
    return "".join(result)


def autokey_decrypt(cipher: str, primer: str) -> str:
    """Autokey cipher - uses plaintext as key after primer"""
    result = ""
    key_stream = list(primer)
    for i, c in enumerate(cipher):
        if c.isalpha():
            if i < len(primer):
                key_char = primer[i]
            else:
                key_char = result[i - len(primer)]
            key_idx = ord(key_char) - ord("A")
            cipher_idx = ord(c) - ord("A")
            plain_idx = (cipher_idx - key_idx) % 26
            result += chr(plain_idx + ord("A"))
        else:
            result += c
    return result


def autokey_enc(ct, seed):
    """Autokey cipher encryption"""
    result = []
    key = list(seed)
    for i, c in enumerate(ct):
        if c in A:
            k = key[i]
            p = n2let((let2n(c) + let2n(k)) % 26)
            result.append(p)
            key.append(p)
    return "".join(result)


def autokey_dec(ct, seed):
    """Autokey cipher decryption"""
    result = []
    key = list(seed)
    for i, c in enumerate(ct):
        if c in A:
            k = key[i]
            p = n2let((let2n(c) - let2n(k)) % 26)
            result.append(p)
            key.append(p)
    return "".join(result)


def running_key_encrypt(plaintext, running_key):
    """Running Key cipher (uses long text as key)"""
    plaintext = clean_text(plaintext)
    running_key = clean_text(running_key)
    return "".join(
        n2let(let2n(c) + let2n(running_key[i]))
        for i, c in enumerate(plaintext)
        if i < len(running_key)
    )


def running_key_decrypt(ciphertext, running_key):
    """Running Key decryption"""
    return "".join(
        n2let((let2n(c) - let2n(running_key[i])) % 26)
        for i, c in enumerate(ciphertext)
        if i < len(running_key) and c in A
    )


def gronsfeld_dec(ct, key):
    """Gronsfeld cipher (numeric key)"""
    key = "".join(d for d in str(key) if d.isdigit())
    return "".join(
        n2let(let2n(c) - int(key[i % len(key)])) for i, c in enumerate(ct) if c in A
    )


def gronsfeld_enc(ct, key):
    """Gronsfeld cipher (numeric key)"""
    key = "".join(d for d in str(key) if d.isdigit())
    return "".join(
        n2let(let2n(c) + int(key[i % len(key)])) for i, c in enumerate(ct) if c in A
    )


def gromark_dec(ct, key):
    """Gromark cipher (key to numbers then subtract)"""
    key = clean(key)
    numkey = "".join(str(let2n(c)) for c in key)
    return "".join(
        n2let((let2n(c) - int(numkey[i % len(numkey)])) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def quagmire_encrypt(plaintext, key, indicator, period):
    """Quagmire cipher (keyed Vigenère)"""
    key_alpha = keyed_alphabet(key)
    ind_alpha = keyed_alphabet(indicator)
    plaintext = clean_text(plaintext)

    result = []
    for i, c in enumerate(plaintext):
        pt_idx = key_alpha.index(c)
        k_idx = let2n(ind_alpha[i % period])
        result.append(n2let((pt_idx + k_idx) % 26))
    return "".join(result)


def quagmire_decrypt(ciphertext, key, indicator, period):
    """Quagmire decryption"""
    key_alpha = keyed_alphabet(key)
    ind_alpha = keyed_alphabet(indicator)
    ciphertext = clean_text(ciphertext)

    result = []
    for i, c in enumerate(ciphertext):
        ct_idx = let2n(c)
        k_idx = let2n(ind_alpha[i % period])
        pt_idx = (ct_idx - k_idx) % 26
        result.append(key_alpha[pt_idx])
    return "".join(result)


def quagmire1_dec(ct, key):
    """Quagmire I (keyed Vigenère with same key for alphabet and crypto)"""
    alpha = keyed_alphabet(key)
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            row_shift = let2n(key[0])
            col = let2n(c)
            plain_pos = (col - k - row_shift) % 26
            result.append(alpha[plain_pos])
        else:
            result.append(c)
    return "".join(result)


def quagmire3_dec(ct, pt_key, vig_key, indicator="A"):
    """Quagmire III (keyed Vigenère)"""
    pt_alpha = keyed_alphabet(pt_key)
    result = []
    for i, c in enumerate(ct):
        if c not in A:
            result.append(c)
            continue
        k = vig_key[i % len(vig_key)]
        row_shift = (let2n(k) - let2n(indicator)) % 26
        col = let2n(c)
        plain_pos = (col - row_shift) % 26
        result.append(pt_alpha[plain_pos])
    return "".join(result)


def quagmire4_dec(ct, pt_key, ind_key, key):
    """Quagmire IV (keyed Vigenère with indicator)"""
    pt_alpha = keyed_alphabet(pt_key)
    ind_alpha = keyed_alphabet(ind_key)
    result = []
    for i, c in enumerate(ct):
        if c not in A:
            result.append(c)
            continue
        ind_letter = ind_alpha[i % len(ind_key)]
        row_shift = let2n(ind_letter)
        k = key[i % len(key)]
        col = (let2n(c) - row_shift - let2n(k)) % 26
        result.append(pt_alpha[col])
    return "".join(result)


# ============================================================================
# ROLLING KEY VARIANTS
# ============================================================================


def rolling_key_v1(ct, key):
    """Rolling key: key[i] + i"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            shift = (k + i) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


def rolling_key_v2(ct, key):
    """Rolling key: cumulative key + position"""
    result = []
    cumsum = 0
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            cumsum = (cumsum + k) % 26
            result.append(n2let((let2n(c) - cumsum - i) % 26))
        else:
            result.append(c)
    return "".join(result)


def rolling_key_v3(ct, key):
    """Rolling key: key[i] + i^2"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            shift = (k + i * i) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


def rolling_key_fibonacci(ct, key):
    """Rolling key with Fibonacci index"""
    fib = [1, 1]
    while len(fib) <= len(ct):
        fib.append(fib[-1] + fib[-2])
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            f = fib[i + 1] % 26
            result.append(n2let((let2n(c) - k - f) % 26))
        else:
            result.append(c)
    return "".join(result)


def rolling_key_prime(ct, key):
    """Rolling key with prime index"""
    primes = []
    n = 2
    while len(primes) <= len(ct):
        is_prime = all(n % p != 0 for p in primes if p * p <= n)
        if is_prime:
            primes.append(n)
        n += 1
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            p = primes[i % len(primes)] % 26
            result.append(n2let((let2n(c) - k - p) % 26))
        else:
            result.append(c)
    return "".join(result)


def rolling_key_sine(ct, key):
    """Rolling key with sine wave modulation"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            wave = int(5 * math.sin(2 * math.pi * i / 15))
            result.append(n2let((let2n(c) - k - wave) % 26))
        else:
            result.append(c)
    return "".join(result)


def rolling_key_rotate(ct, key):
    """Rolling key with rotating key"""
    result = []
    key = list(key)
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[0])
            shift = (k + i) % 26
            result.append(n2let((let2n(c) - shift) % 26))
            key = key[1:] + key[:1]
        else:
            result.append(c)
    return "".join(result)


def rolling_key_cipher_feedback(ct, key, fb_len=3):
    """Rolling key with cipher feedback"""
    result = []
    key = list(key)
    fb = []
    for i, c in enumerate(ct):
        if c in A:
            k_idx = i % len(key)
            k = let2n(key[k_idx])
            shift = (k + i) % 26
            p = n2let((let2n(c) - shift) % 26)
            result.append(p)
            fb.append(c)
            if len(fb) > fb_len:
                fb.pop(0)
                key[k_idx] = n2let((let2n(key[k_idx]) + let2n(fb[-1])) % 26)
        else:
            result.append(c)
    return "".join(result)


def rolling_key_interleaved(ct, key):
    """Two keys interleaved"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k1 = let2n(key[i % len(key)])
            k2 = let2n(key[(i * 3 + 1) % len(key)])
            shift = (k1 + k2) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


# ============================================================================
# POLYBIUS AND GRID CIPHERS
# ============================================================================


def polybius_encrypt(plaintext, square=None):
    """Polybius square encryption"""
    if square is None:
        square = A

    plaintext = clean_text(plaintext)
    result = []
    for c in plaintext:
        idx = square.index(c)
        row, col = idx // 5 + 1, idx % 5 + 1
        result.append(f"{row}{col}")
    return "".join(result)


def polybius_decrypt(numbers, square=None):
    """Polybius square decryption"""
    if square is None:
        square = A

    numbers = numbers.replace(" ", "")
    result = []
    for i in range(0, len(numbers) - 1, 2):
        if numbers[i : i + 2].isdigit():
            row, col = int(numbers[i]), int(numbers[i + 1])
            if 1 <= row <= 5 and 1 <= col <= 5:
                idx = (row - 1) * 5 + (col - 1)
                if idx < len(square):
                    result.append(square[idx])
    return "".join(result)


def straddling_checkerboard_encrypt(plaintext, keyword):
    """Straddling checkerboard cipher"""
    keyword = clean_text(keyword)
    square = keyed_alphabet(keyword)

    plaintext = clean_text(plaintext)
    result = []
    for c in plaintext:
        idx = square.index(c)
        if idx < 10:
            result.append(str(idx))
        else:
            row = (idx - 10) // 8 + 1
            col = (idx - 10) % 8 + 1
            result.append(f"{row}{col}")
    return "".join(result)


def straddling_checkerboard_decrypt(numbers, keyword):
    """Straddling checkerboard decryption"""
    keyword = clean_text(keyword)
    square = keyed_alphabet(keyword)

    numbers = numbers.replace(" ", "")
    result = []
    i = 0
    while i < len(numbers):
        digit = numbers[i]
        if digit == "0":
            if i + 1 < len(numbers):
                idx = 10 + int(numbers[i + 1])
                result.append(square[idx])
                i += 2
        elif digit == "1":
            if i + 1 < len(numbers):
                idx = 18 + int(numbers[i + 1])
                result.append(square[idx])
                i += 2
        else:
            result.append(square[int(digit)])
            i += 1
    return "".join(result)


# ============================================================================
# TRANSPOSITION CIPHERS
# ============================================================================


def columnar_transpose_encrypt(plaintext, keyword):
    """Columnar transposition cipher"""
    plaintext = clean_text(plaintext)
    keyword = clean_text(keyword)

    num_cols = len(keyword)
    num_rows = (len(plaintext) + num_cols - 1) // num_cols

    padded = plaintext.ljust(num_rows * num_cols, "X")

    grid = [padded[i * num_cols : (i + 1) * num_cols] for i in range(num_rows)]

    order = sorted(range(num_cols), key=lambda i: keyword[i])

    result = []
    for col in order:
        for row in range(num_rows):
            result.append(grid[row][col])

    return "".join(result)


def columnar_transpose_decrypt(ciphertext, keyword):
    """Columnar transposition decryption"""
    keyword = clean(keyword)
    if not keyword:
        return ciphertext
    key_order = sorted(range(len(keyword)), key=lambda i: keyword[i])
    cols = len(keyword)
    rows = len(ciphertext) // cols + (1 if len(ciphertext) % cols else 0)
    grid = [
        list(
            ciphertext[i * cols : (i + 1) * cols]
            + " " * (cols - len(ciphertext[i * cols : (i + 1) * cols]))
        )
        for i in range(rows)
    ]
    return "".join(
        grid[r][c] for c in key_order for r in range(rows) if c < len(grid[r])
    )


def columnar_dec(ct, key):
    """Columnar transposition decryption"""
    key = clean(key)
    if not key:
        return ct
    key_order = sorted(range(len(key)), key=lambda i: key[i])
    cols = len(key)
    rows = len(ct) // cols + (1 if len(ct) % cols else 0)
    grid = [
        list(
            ct[i * cols : (i + 1) * cols]
            + " " * (cols - len(ct[i * cols : (i + 1) * cols]))
        )
        for i in range(rows)
    ]
    return "".join(
        grid[r][c] for c in key_order for r in range(rows) if c < len(grid[r])
    )


def columnar_enc(pt, key):
    """Columnar transposition encryption"""
    key = clean(key)
    if not key:
        return pt
    key_order = sorted(range(len(key)), key=lambda i: key[i])
    cols = len(key)
    rows = (len(pt) + cols - 1) // cols
    pt = pt + "X" * (rows * cols - len(pt))
    grid = [list(pt[i * cols : (i + 1) * cols]) for i in range(rows)]
    return "".join(
        grid[r][c]
        for c in range(cols)
        for r in range(rows)
        if c < len(grid[r]) and grid[r][c] != " "
    )


def columnar_transpose_decrypt_v1(cipher: str, key_len: int) -> str:
    """Columnar transposition decryption (by key length)"""
    cols = key_len
    rows = (len(cipher) + cols - 1) // cols
    num_filled = len(cipher) % cols if len(cipher) % cols != 0 else cols

    col_lengths = [rows] * cols
    for i in range(cols - num_filled):
        col_lengths[i] = rows - 1

    matrix = [[""] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(col_lengths[c]):
            if idx < len(cipher):
                matrix[r][c] = cipher[idx]
                idx += 1

    result = ""
    for r in range(rows):
        for c in range(cols):
            if matrix[r][c]:
                result += matrix[r][c]
    return result


def rail_fence_dec(ct, rails):
    """Rail fence transposition decryption"""
    if rails < 2:
        return ct
    fence = [[] for _ in range(rails)]
    direction, row = 1, 0
    for c in ct:
        fence[row].append(c)
        row += direction
        if row == 0 or row == rails - 1:
            direction *= -1
    return "".join(c for line in fence for c in line)


def rail_fence_enc(pt, rails):
    """Rail fence transposition encryption"""
    return rail_fence_dec(pt, rails)


def rail_fence_decrypt(cipher: str, rails: int) -> str:
    """Rail fence transposition (v1)"""
    if rails < 2:
        return cipher

    pattern = [
        i % (rails - 1) if i % (rails - 1) != 0 else rails - 1
        for i in range(len(cipher))
    ]
    matrix = [""] * rails
    for i, c in enumerate(cipher):
        row = pattern[i]
        matrix[row] += c

    result = ""
    idx = 0
    for i in range(len(cipher)):
        row = pattern[i]
        result += matrix[row][0]
        matrix[row] = matrix[row][1:]
    return result


def scytale_dec(ct, rows):
    """Scytale cipher decryption"""
    cols = len(ct) // rows
    if len(ct) % rows:
        cols += 1
    grid = [ct[i * cols : (i + 1) * cols] for i in range(rows)]
    return "".join(
        grid[r][c] for c in range(cols) for r in range(rows) if c < len(grid[r])
    )


def scytale_enc(pt, rows):
    """Scytale cipher encryption"""
    return scytale_dec(pt, rows)


def scytale_decrypt(cipher: str, rods: int) -> str:
    """Scytale cipher decryption (v1)"""
    rows = len(cipher) // rods
    if len(cipher) % rods != 0:
        rows += 1

    matrix = [[""] * rods for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(rods):
            if idx < len(cipher):
                matrix[r][c] = cipher[idx]
                idx += 1

    result = ""
    for c in range(rods):
        for r in range(rows):
            result += matrix[r][c]
    return result


def double_transposition_encrypt(plaintext, key1, key2):
    """Double columnar transposition"""
    temp = columnar_transpose_encrypt(plaintext, key1)
    return columnar_transpose_encrypt(temp, key2)


def double_transposition_decrypt(ciphertext, key1, key2):
    """Double columnar transposition decryption"""
    temp = columnar_transpose_decrypt(ciphertext, key2)
    return columnar_transpose_decrypt(temp, key1)


def double_transpose_decrypt(cipher: str, k1: int, k2: int) -> str:
    """Double columnar transposition (v1)"""
    return columnar_transpose_decrypt_v1(columnar_transpose_decrypt_v1(cipher, k1), k2)


def zigzag_decrypt(cipher: str, depth: int) -> str:
    """Zigzag transposition"""
    if depth < 2:
        return cipher

    rows = [""] * depth
    direction = 1
    row = 0

    for c in cipher:
        rows[row] += c
        row += direction
        if row >= depth:
            direction = -1
            row = depth - 1
        elif row < 0:
            direction = 1
            row = 0

    return "".join(rows)


def diagonal_read_decrypt(cipher: str, width: int) -> str:
    """Diagonal reading transposition"""
    result = ""
    for start in range(width):
        for i in range(start, len(cipher), width):
            result += cipher[i]
    return result


def myszkowski_decrypt(cipher: str, key: str) -> str:
    """Myszkowski transposition"""
    key_len = len(key)
    key_order = sorted(range(key_len), key=lambda i: key[i])
    rows = (len(cipher) + key_len - 1) // key_len
    matrix = [[""] * key_len for _ in range(rows)]

    idx = 0
    for col in key_order:
        for row in range(rows):
            if idx < len(cipher):
                matrix[row][col] = cipher[idx]
                idx += 1

    result = ""
    for row in range(rows):
        for col in range(key_len):
            result += matrix[row][col]
    return result


def irregular_columnar_dec(ct, key):
    """Irregular columnar transposition"""
    key = clean(key)
    if not key:
        return ct
    key_order = sorted(range(len(key)), key=lambda i: key[i])
    cols = len(key)
    rows = len(ct) // cols + (1 if len(ct) % cols else 0)
    grid = [
        list(
            ct[i * cols : (i + 1) * cols]
            + " " * (cols - len(ct[i * cols : (i + 1) * cols]))
        )
        for i in range(rows)
    ]
    return "".join(
        grid[r][c] for c in key_order for r in range(rows) if c < len(grid[r])
    )


def route_transpose_encrypt(plaintext, rows, cols, route="spiral"):
    """Route transposition cipher"""
    plaintext = clean_text(plaintext)
    plaintext = plaintext.ljust(rows * cols, "X")

    grid = [[plaintext[i * cols + j] for j in range(cols)] for i in range(rows)]

    if route == "spiral":
        result = []
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        while top <= bottom and left <= right:
            for j in range(left, right + 1):
                result.append(grid[top][j])
            top += 1
            for i in range(top, bottom + 1):
                result.append(grid[i][right])
            right -= 1
            if top <= bottom:
                for j in range(right, left - 1, -1):
                    result.append(grid[bottom][j])
                bottom -= 1
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    result.append(grid[i][left])
                left += 1
        return "".join(result)

    return plaintext


# ============================================================================
# DIGRAPH CIPHERS
# ============================================================================


def playfair_encrypt(plaintext, keyword):
    """Playfair cipher encryption"""
    square = keyed_alphabet(keyword)
    plaintext = clean_text(plaintext)

    digrams = []
    i = 0
    while i < len(plaintext):
        if i + 1 < len(plaintext) and plaintext[i] != plaintext[i + 1]:
            digrams.append(plaintext[i] + plaintext[i + 1])
            i += 2
        else:
            digrams.append(plaintext[i] + "X")
            i += 1

    result = []
    for d in digrams:
        c1, c2 = d[0], d[1]
        r1, c1_idx = divmod(square.index(c1), 5)
        r2, c2_idx = divmod(square.index(c2), 5)

        if r1 == r2:
            c1_idx = (c1_idx + 1) % 5
            c2_idx = (c2_idx + 1) % 5
        elif c1_idx == c2_idx:
            r1 = (r1 + 1) % 5
            r2 = (r2 + 1) % 5
        else:
            c1_idx, c2_idx = c2_idx, c1_idx

        result.append(square[r1 * 5 + c1_idx])
        result.append(square[r2 * 5 + c2_idx])

    return "".join(result)


def playfair_decrypt(ciphertext, keyword):
    """Playfair cipher decryption"""
    square = keyed_alphabet(keyword)
    ciphertext = clean_text(ciphertext)

    result = []
    for i in range(0, len(ciphertext), 2):
        c1, c2 = ciphertext[i], ciphertext[i + 1]
        r1, c1_idx = divmod(square.index(c1), 5)
        r2, c2_idx = divmod(square.index(c2), 5)

        if r1 == r2:
            c1_idx = (c1_idx - 1) % 5
            c2_idx = (c2_idx - 1) % 5
        elif c1_idx == c2_idx:
            r1 = (r1 - 1) % 5
            r2 = (r2 - 1) % 5
        else:
            c1_idx, c2_idx = c2_idx, c1_idx

        result.append(square[r1 * 5 + c1_idx])
        result.append(square[r2 * 5 + c2_idx])

    return "".join(result)


def playfair_dec(ct, key):
    """Playfair cipher decryption (v3)"""
    grid = []
    alpha = keyed_alphabet(key)
    for i in range(5):
        grid.append(list(alpha[i * 5 : (i + 1) * 5]))

    ct = ct.upper().replace("J", "I")
    result = []
    for i in range(0, len(ct) - 1, 2):
        a, b = ct[i], ct[i + 1]
        if a not in A or b not in A:
            result.extend([a, b])
            continue
        for r in range(5):
            for c in range(5):
                if grid[r][c] == a:
                    ra, ca = r, c
                if grid[r][c] == b:
                    rb, cb = r, c
        if ra == rb:
            result.append(grid[ra][(ca - 1) % 5])
            result.append(grid[rb][(cb - 1) % 5])
        elif ca == cb:
            result.append(grid[(ra - 1) % 5][ca])
            result.append(grid[(rb - 1) % 5][cb])
        else:
            result.append(grid[ra][cb])
            result.append(grid[rb][ca])
    return "".join(result)


def foursquare_encrypt(plaintext, key1, key2):
    """Four-Square cipher encryption"""
    upper = keyed_alphabet(key1)
    lower = keyed_alphabet(key2)
    plaintext = clean_text(plaintext)

    result = []
    for i in range(0, len(plaintext) - 1, 2):
        p1, p2 = plaintext[i], plaintext[i + 1]

        r1, c1 = divmod(upper.index(p1), 5)
        r2, c2 = divmod(lower.index(p2), 5)

        result.append(upper[r1 * 5 + c2])
        result.append(lower[r2 * 5 + c1])

    return "".join(result)


def foursquare_decrypt(ciphertext, key1, key2):
    """Four-Square cipher decryption"""
    upper = keyed_alphabet(key1)
    lower = keyed_alphabet(key2)
    ciphertext = clean_text(ciphertext)

    result = []
    for i in range(0, len(ciphertext) - 1, 2):
        c1, c2 = ciphertext[i], ciphertext[i + 1]

        r1, c1_idx = divmod(upper.index(c1), 5)
        r2, c2_idx = divmod(lower.index(c2), 5)

        result.append(upper[r1 * 5 + c2_idx])
        result.append(lower[r2 * 5 + c1_idx])

    return "".join(result)


def threesquare_dec(ct, key1, key2):
    """Three-square cipher decryption"""
    sq1 = keyed_alphabet(key1)
    sq2 = keyed_alphabet(key2)

    def find_pos(sq, c):
        p = sq.index(c)
        return p // 5, p % 5

    result = []
    for i in range(0, len(ct) - 1, 2):
        if ct[i] in A and ct[i + 1] in A:
            r1, c1 = find_pos(sq1, ct[i])
            r2, c2 = find_pos(sq2, ct[i + 1])
            result.append(sq1[r1 * 5 + c2])
            result.append(sq2[r2 * 5 + c1])
        else:
            result.extend([ct[i], ct[i + 1] if i + 1 < len(ct) else ""])
    return "".join(result)


# ============================================================================
# FRACTIONATED CIPHERS
# ============================================================================


def bifid_encrypt(plaintext, keyword, period=5):
    """Bifid cipher encryption"""
    square = keyed_alphabet(keyword)
    plaintext = clean_text(plaintext)

    coords = []
    for c in plaintext:
        idx = square.index(c)
        row, col = idx // 5 + 1, idx % 5 + 1
        coords.append((row, col))

    result = []
    for i in range(0, len(coords), period):
        col_coords = [c[0] for c in coords[i : i + period]]
        row_coords = [c[1] for c in coords[i : i + period]]
        for r, c in zip(row_coords, col_coords):
            result.append(f"{r}{c}")

    return "".join(result)


def bifid_decrypt(ciphertext, keyword, period=5):
    """Bifid cipher decryption"""
    square = keyed_alphabet(keyword)
    ciphertext = ciphertext.replace(" ", "")

    if len(ciphertext) % 2 != 0:
        ciphertext = ciphertext[:-1]

    coords = []
    for i in range(0, len(ciphertext) - 1, 2):
        row, col = int(ciphertext[i]), int(ciphertext[i + 1])
        coords.append((row, col))

    row_coords = [c[0] for c in coords]
    col_coords = [c[1] for c in coords]

    result = []
    for i in range(period):
        row_i = row_coords[i::period]
        col_i = col_coords[i::period]

        for r, c in zip(row_i, col_i):
            idx = (r - 1) * 5 + (c - 1)
            if idx < len(square):
                result.append(square[idx])

    return "".join(result)


def bifid_dec(ct, key, period):
    """Bifid cipher decryption (v3)"""
    sq = make_polybius(key)

    def pos(c):
        i = sq.index(c if c != "J" else "I")
        return i // 5, i % 5

    def from_pos(r, c):
        return sq[r * 5 + c]

    ct = ct.replace("J", "I")
    result = []
    for bs in range(0, len(ct), period):
        block = ct[bs : bs + period]
        pairs = [pos(c) for c in block]
        rows = [p[0] for p in pairs]
        cols = [p[1] for p in pairs]
        combined = rows + cols
        for i in range(len(block)):
            result.append(from_pos(combined[i], combined[i + len(block)]))
    return "".join(result)


def trifid_encrypt(plaintext, keyword, period=5):
    """Trifid cipher encryption"""
    layer1 = "ABCDEFGHIJKLM"
    layer2 = "NOPQRSTUVWXYZ"
    alphabet = layer1 + layer2 + layer1[:1]

    plaintext = clean_text(plaintext)

    coords = []
    for c in plaintext:
        idx = alphabet.index(c)
        layer = idx // 9 + 1
        row = (idx % 9) // 3 + 1
        col = idx % 3 + 1
        coords.append((layer, row, col))

    result = []
    for i in range(0, len(coords), period):
        for dim in range(3):
            for j in range(i, min(i + period, len(coords))):
                result.append(str(coords[j][dim]))

    return "".join(result)


def trifid_decrypt(ciphertext, keyword, period=5):
    """Trifid cipher decryption"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = ciphertext.replace(" ", "")

    coords = []
    for i in range(0, len(ciphertext) - 2, 3):
        layer = int(ciphertext[i])
        row = int(ciphertext[i + 1])
        col = int(ciphertext[i + 2])
        coords.append((layer, row, col))

    result = []
    num_full = len(coords) // period
    for i in range(period):
        row_coords = coords[i::period][:num_full]
        col_coords = coords[
            i + num_full * period : i + num_full * period + len(row_coords)
        ]

        for r, c in zip(row_coords, col_coords):
            idx = (r[0] - 1) * 9 + (r[1] - 1) * 3 + (r[2] - 1)
            result.append(alphabet[idx])

    return "".join(result)


# ============================================================================
# HILL CIPHER
# ============================================================================


def hill_dec(ct, key_matrix):
    """Hill cipher decryption (2x2 matrix)"""
    if len(key_matrix) != 2 or len(key_matrix[0]) != 2:
        raise ValueError("Only 2x2 Hill cipher supported")

    det = key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]
    det_inv = pow(det % 26, -1, 26)
    adj = [[key_matrix[1][1], -key_matrix[0][1]], [-key_matrix[1][0], key_matrix[0][0]]]
    inv = [[(det_inv * adj[i][j]) % 26 for j in range(2)] for i in range(2)]

    result = []
    for i in range(0, len(ct) - (len(ct) % 2), 2):
        v = [let2n(ct[i]), let2n(ct[i + 1])]
        p = [
            (inv[0][0] * v[0] + inv[0][1] * v[1]) % 26,
            (inv[1][0] * v[0] + inv[1][1] * v[1]) % 26,
        ]
        result.extend([n2let(p[0]), n2let(p[1])])
    if len(ct) % 2:
        result.append(ct[-1])
    return "".join(result)


def hill_enc(pt, key_matrix):
    """Hill cipher encryption (2x2 matrix)"""
    if len(key_matrix) != 2 or len(key_matrix[0]) != 2:
        raise ValueError("Only 2x2 Hill cipher supported")

    result = []
    for i in range(0, len(pt) - (len(pt) % 2), 2):
        v = [let2n(pt[i]), let2n(pt[i + 1])]
        c = [
            (key_matrix[0][0] * v[0] + key_matrix[0][1] * v[1]) % 26,
            (key_matrix[1][0] * v[0] + key_matrix[1][1] * v[1]) % 26,
        ]
        result.extend([n2let(c[0]), n2let(c[1])])
    if len(pt) % 2:
        result.append(pt[-1])
    return "".join(result)


# ============================================================================
# MATHEMATICAL/PATTERN CIPHERS
# ============================================================================


def multiplication_decrypt(cipher: str, multiplier: int) -> str:
    """Multiplication cipher (requires multiplier coprime to 26)"""
    inverse = None
    for i in range(26):
        if (multiplier * i) % 26 == 1:
            inverse = i
            break

    if inverse is None:
        return None

    result = ""
    for c in cipher:
        if c.isalpha():
            c_idx = ord(c) - ord("A")
            plain = (c_idx * inverse) % 26
            result += chr(plain + ord("A"))
        else:
            result += c
    return result


def progressive_shift_decrypt(cipher: str, seed: int = 0) -> str:
    """Progressive shift where shift increases by 1 each letter"""
    result = ""
    shift = seed
    for c in cipher:
        if c.isalpha():
            result += chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
            shift = (shift + 1) % 26
        else:
            result += c
    return result


def position_based_shift_decrypt(cipher: str, base: int = 0) -> str:
    """Shift each letter by its position in the string"""
    result = ""
    for i, c in enumerate(cipher):
        if c.isalpha():
            shift = (i + base) % 26
            result += chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
        else:
            result += c
    return result


def serial_shift_decrypt(cipher: str) -> str:
    """Shift by sequential position (1,2,3,...)"""
    return position_based_shift_decrypt(cipher, 0)


def cumulative_shift_decrypt(cipher: str) -> str:
    """Cumulative shift - each letter shifted by running total"""
    result = ""
    total = 0
    for c in cipher:
        if c.isalpha():
            total = (total + 1) % 26
            result += chr((ord(c) - ord("A") - total) % 26 + ord("A"))
        else:
            result += c
    return result


def prime_position_decrypt(cipher: str) -> str:
    """Shift by prime numbers based on position"""
    primes = []
    num = 2
    while len(primes) < 50:
        is_prime = True
        for p in primes:
            if num % p == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
        num += 1

    result = ""
    for i, c in enumerate(cipher):
        if c.isalpha():
            shift = primes[i] % 26 if i < len(primes) else i % 26
            result += chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
        else:
            result += c
    return result


def fibonacci_shift_decrypt(cipher: str) -> str:
    """Shift by Fibonacci numbers"""
    fibs = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]
    result = ""
    for i, c in enumerate(cipher):
        if c.isalpha():
            shift = fibs[i % len(fibs)]
            result += chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
        else:
            result += c
    return result


# ============================================================================
# TRANSFORMATION CIPHERS
# ============================================================================


def reverse_text(cipher: str) -> str:
    """Reverse the entire text"""
    return cipher[::-1]


def every_nth_char(cipher: str, n: int, start: int = 0) -> str:
    """Extract every nth character"""
    return cipher[start::n]


def xor_cipher(ct, key):
    """XOR-like cipher with key"""
    key = clean(key)
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            result.append(n2let((let2n(c) ^ k) % 26))
        else:
            result.append(c)
    return "".join(result)


def pair_swap_decrypt(cipher: str, interval: int = 1) -> str:
    """Swap letters in pairs"""
    result = list(cipher)
    for i in range(0, len(cipher) - 1, interval):
        if result[i].isalpha() and result[i + 1].isalpha():
            result[i], result[i + 1] = result[i + 1], result[i]
    return "".join(result)


def complement_decrypt(cipher: str, shift: int = 0) -> str:
    """Complement (A<->Z) with optional shift"""
    result = ""
    for c in cipher:
        if c.isalpha():
            idx = ord(c) - ord("A")
            comp = 25 - idx
            result += chr((comp + shift) % 26 + ord("A"))
        else:
            result += c
    return result


def bazeries_dec(ct, key):
    """Bazeries cipher - keyed alphabet + reversal"""
    alphabet = keyed_alphabet(key)

    def sub(c):
        if c in A:
            return alphabet[25 - alphabet.index(c)]
        return c

    return "".join(sub(c) for c in ct)


# ============================================================================
# ADVANCED/MODERN-STYLE
# ============================================================================


def two_key_interleave_decrypt(cipher: str, k1: str, k2: str) -> str:
    """Use two keys alternatively"""
    result = ""
    for i, c in enumerate(cipher):
        if c.isalpha():
            k = (
                ord(k1[i % len(k1)]) - ord("A")
                if i % 2 == 0
                else ord(k2[i % len(k2)]) - ord("A")
            )
            result += chr((ord(c) - ord("A") - k) % 26 + ord("A"))
        else:
            result += c
    return result


def double_decrypt(cipher: str, k1: str, k2: str) -> str:
    """Apply two rounds of Vigenère"""
    first = vigenere_decrypt(cipher, k1)
    return vigenere_decrypt(first, k2)


def shifted_alphabet_decrypt(cipher: str, key: str, change_period: int = 3) -> str:
    """Vigenère but alphabet changes periodically"""
    result = ""
    for i, c in enumerate(cipher):
        if c.isalpha():
            if i % change_period == 0:
                shift = 1
            elif i % change_period == 1:
                shift = 2
            else:
                shift = 3
            k = ord(key[i % len(key)]) - ord("A")
            result += chr((ord(c) - ord("A") - k - shift) % 26 + ord("A"))
        else:
            result += c
    return result


def key_direction_decrypt(cipher: str, key: str) -> str:
    """Key determines shift direction"""
    result = ""
    for i, c in enumerate(cipher):
        if c.isalpha():
            k = ord(key[i % len(key)]) - ord("A")
            if k % 2 == 0:
                shift = k
            else:
                shift = -k
            result += chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
        else:
            result += c
    return result


def cipher_feedback_decrypt(cipher: str, primer: str) -> str:
    """Cipher feedback mode"""
    result = ""
    key = list(primer)
    for i, c in enumerate(cipher):
        if c.isalpha():
            k = ord(key[i % len(key)]) - ord("A")
            plain = (ord(c) - ord("A") - k) % 26
            result += chr(plain + ord("A"))
            key.append(chr(plain + ord("A")))
        else:
            result += c
    return result


def additive_feedback_decrypt(cipher: str, seed: int) -> str:
    """Additive with feedback"""
    result = ""
    state = seed
    for c in cipher:
        if c.isalpha():
            c_idx = ord(c) - ord("A")
            plain = (c_idx - state) % 26
            result += chr(plain + ord("A"))
            state = (state + plain) % 26
        else:
            result += c
    return result


# ============================================================================
# SECTION-SPECIFIC KEYS
# ============================================================================


def section_key_dec(ct, keys, section_sizes):
    """Different keys for different sections"""
    result = []
    sec_idx = 0
    for i, c in enumerate(ct):
        if c in A:
            pos_in_sec = (
                sum(section_sizes[: sec_idx + 1])
                if i >= sum(section_sizes[: sec_idx + 1])
                else i - sum(section_sizes[:sec_idx])
            )
            if i >= sum(section_sizes[: sec_idx + 1]):
                sec_idx = min(sec_idx + 1, len(keys) - 1)
            key = keys[sec_idx % len(keys)]
            k = let2n(key[pos_in_sec % len(key)])
            shift = (k + i) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


def block_key_dec(ct, keys):
    """Different key for each block"""
    result = []
    n_keys = len(keys)
    block_size = len(ct) // n_keys
    for i, c in enumerate(ct):
        if c in A:
            block_idx = min(i // block_size, n_keys - 1)
            key = keys[block_idx]
            pos_in_block = i % block_size
            k = let2n(key[pos_in_block % len(key)])
            result.append(n2let((let2n(c) - k) % 26))
        else:
            result.append(c)
    return "".join(result)


def alternating_keys_dec(ct, key1, key2, pattern):
    """Switch between keys based on pattern"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            if pattern[i % len(pattern)] == "A":
                k = let2n(key1[i % len(key1)])
            else:
                k = let2n(key2[i % len(key2)])
            shift = (k + i) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


# ============================================================================
# HIGHER-ORDER CIPHERS
# ============================================================================


def progressive_vigenere(ct, key, start=1):
    """Progressive Vigenère - shift key by position"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            shift = (let2n(key[i % len(key)]) + i + start - 1) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


def cdp_dec(ct, key):
    """CDP cipher (multiplication)"""
    return "".join(
        n2let((let2n(c) * let2n(key[i % len(key)])) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def cunningham_dec(ct, key):
    """Cunningham cipher"""
    return "".join(
        n2let((let2n(c) + let2n(key[i % len(key)]) * (i + 1)) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def slidefair_dec(ct, key):
    """Slidefair cipher"""
    result = []
    for i, c in enumerate(ct):
        if c in A:
            shift = let2n(key[i % len(key)])
            shift = shift * (i + 1) % 26
            result.append(n2let((let2n(c) - shift) % 26))
        else:
            result.append(c)
    return "".join(result)


def cadenian_dec(ct, key):
    """Cadenus cipher variant"""
    return "".join(
        n2let((let2n(c) - let2n(key[i % len(key)]) - i) % 26)
        for i, c in enumerate(ct)
        if c in A
    )


def ragbaby_dec(ct, key):
    """Ragbaby cipher"""
    key = clean(key)
    result = []
    for i, c in enumerate(ct):
        if c in A:
            k = let2n(key[i % len(key)])
            offset = len([x for x in result if x in A]) + 1
            result.append(n2let((let2n(c) - k - offset) % 26))
        else:
            result.append(c)
    return "".join(result)


# ============================================================================
# ENIGMA (Simplified 3-Rotor)
# ============================================================================


ENIGMA_ROTORS = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}

ENIGMA_REFLECTORS = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}


class Enigma:
    """Simplified 3-rotor Enigma machine."""

    def __init__(self, rotors, reflector, ring_settings="AAA", start_positions="AAA"):
        self.rotors = [list(ENIGMA_ROTORS[r]) for r in rotors]
        self.rotor_notches = [ENIGMA_ROTORS[r][1] for r in rotors]
        self.reflector = list(ENIGMA_REFLECTORS[reflector])
        self.ring_settings = [let2n(c) for c in ring_settings]
        self.positions = [let2n(c) for c in start_positions]

    def _step(self):
        """Step the rotors."""
        if self.positions[1] == let2n(self.rotor_notches[1]):
            self.positions[0] = (self.positions[0] + 1) % 26
        if self.positions[1] == let2n(self.rotor_notches[1]):
            self.positions[1] = (self.positions[1] + 1) % 26
        self.positions[1] = (self.positions[1] + 1) % 26

    def _encrypt_letter(self, c):
        """Encrypt a single letter."""
        self._step()

        for i in range(3):
            idx = (let2n(c) + self.positions[i] - self.ring_settings[i]) % 26
            c = self.rotors[i][idx]

        idx = self.reflector.index(c)
        c = self.reflector[idx]

        for i in range(2, -1, -1):
            idx = self.rotors[i].index(c)
            idx = (idx - self.positions[i] + self.ring_settings[i]) % 26
            c = A[idx]

        return c

    def encrypt(self, plaintext):
        """Encrypt plaintext."""
        plaintext = clean_text(plaintext)
        result = []
        for c in plaintext:
            result.append(self._encrypt_letter(c))
        return "".join(result)

    def decrypt(self, ciphertext):
        """Decrypt (Enigma is self-inverse)."""
        return self.encrypt(ciphertext)


def enigma_dec(ct, r1n, r2n, r3n, refn, p1, p2, p3):
    """Simplified 3-rotor Enigma decryption"""
    fwd1 = [ord(c) - 65 for c in ENIGMA_ROTORS[r1n][0]]
    fwd2 = [ord(c) - 65 for c in ENIGMA_ROTORS[r2n][0]]
    fwd3 = [ord(c) - 65 for c in ENIGMA_ROTORS[r3n][0]]
    bwd1 = [0] * 26
    [bwd1.__setitem__(v, i) for i, v in enumerate(fwd1)]
    bwd2 = [0] * 26
    [bwd2.__setitem__(v, i) for i, v in enumerate(fwd2)]
    bwd3 = [0] * 26
    [bwd3.__setitem__(v, i) for i, v in enumerate(fwd3)]
    ref = [ord(c) - 65 for c in ENIGMA_REFLECTORS[refn]]
    ntch2 = set(ord(c) - 65 for c in ENIGMA_ROTORS[r2n][1])
    ntch3 = set(ord(c) - 65 for c in ENIGMA_ROTORS[r3n][1])

    pos1, pos2, pos3 = p1, p2, p3
    result = []
    for c in ct:
        if pos2 in ntch2:
            pos2 = (pos2 + 1) % 26
            pos1 = (pos1 + 1) % 26
        elif pos3 in ntch3:
            pos2 = (pos2 + 1) % 26
        pos3 = (pos3 + 1) % 26
        s = ord(c) - 65
        s = (fwd3[s] - pos3) % 26
        s = (fwd2[s - pos2 + pos2] - pos2) % 26
        s = (fwd1[s - pos1 + pos1] - pos1) % 26
        s = ref[s]
        s = (bwd1[s - pos1 + pos1] - pos1) % 26
        s = (bwd2[s - pos2 + pos2] - pos2) % 26
        s = (bwd3[s - pos3 + pos3] - pos3) % 26
        result.append(chr(s + 65))
    return "".join(result)


# ============================================================================
# HOMOPHONIC AND OTHER CIPHERS
# ============================================================================


def homophonic_encrypt(plaintext, mapping):
    """Homophonic substitution cipher"""
    plaintext = clean_text(plaintext)
    result = []
    for c in plaintext:
        if c in mapping:
            result.append(mapping[c][0])
        else:
            result.append(c)
    return "".join(result)


def morse_encrypt(plaintext):
    """Convert text to Morse code."""
    MORSE_CODE = {
        "A": ".-",
        "B": "-...",
        "C": "-.-.",
        "D": "-..",
        "E": ".",
        "F": "..-.",
        "G": "--.",
        "H": "....",
        "I": "..",
        "J": ".---",
        "K": "-.-",
        "L": ".-..",
        "M": "--",
        "N": "-.",
        "O": "---",
        "P": ".--.",
        "Q": "--.-",
        "R": ".-.",
        "S": "...",
        "T": "-",
        "U": "..-",
        "V": "...-",
        "W": ".--",
        "X": "-..-",
        "Y": "-.--",
        "Z": "--..",
        " ": "/",
    }

    plaintext = clean_text(plaintext)
    return " ".join(MORSE_CODE.get(c, "") for c in plaintext)


def morse_decrypt(morse):
    """Convert Morse code to text."""
    MORSE_CODE = {
        v: k
        for k, v in {
            "A": ".-",
            "B": "-...",
            "C": "-.-.",
            "D": "-..",
            "E": ".",
            "F": "..-.",
            "G": "--.",
            "H": "....",
            "I": "..",
            "J": ".---",
            "K": "-.-",
            "L": ".-..",
            "M": "--",
            "N": "-.",
            "O": "---",
            "P": ".--.",
            "Q": "--.-",
            "R": ".-.",
            "S": "...",
            "T": "-",
            "U": "..-",
            "V": "...-",
            "W": ".--",
            "X": "-..-",
            "Y": "-.--",
            "Z": "--..",
            " ": "/",
        }.items()
    }

    return "".join(MORSE_CODE.get(c, "") for c in morse.split())


# ============================================================================
# STATISTICAL ANALYSIS
# ============================================================================


def index_of_coincidence(text):
    """Calculate Index of Coincidence"""
    text = [c for c in text if c in A]
    n = len(text)
    if n < 2:
        return 0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def chi_squared(text, freq=None):
    """Calculate chi-squared statistic vs English frequencies."""
    if freq is None:
        freq = {
            "E": 12.70,
            "T": 9.06,
            "A": 8.17,
            "O": 7.51,
            "I": 6.97,
            "N": 6.75,
            "S": 6.33,
            "H": 6.09,
            "R": 5.98,
            "D": 4.25,
            "L": 4.03,
            "C": 2.78,
            "U": 2.76,
            "M": 2.41,
            "W": 2.36,
            "F": 2.23,
            "G": 2.02,
            "Y": 1.97,
            "P": 1.93,
            "B": 1.52,
            "V": 0.98,
            "K": 0.77,
            "J": 0.15,
            "X": 0.15,
            "Q": 0.10,
            "Z": 0.07,
        }

    text = clean_text(text)
    if len(text) == 0:
        return 0

    observed = Counter(text)
    expected = [freq.get(c, 0) / 100 * len(text) for c in A]
    observed_vals = [observed.get(c, 0) for c in A]

    chi_sq = sum(
        (o - e) ** 2 / e if e > 0 else 0 for o, e in zip(observed_vals, expected)
    )
    return chi_sq


def ngram_score(text, n=2):
    """Calculate n-gram frequency score."""
    BIGRAMS = {
        "TH": 151,
        "HE": 147,
        "IN": 111,
        "ER": 110,
        "AN": 109,
        "RE": 104,
        "ON": 101,
        "AT": 93,
        "EN": 91,
        "ND": 90,
    }

    text = clean_text(text)
    if len(text) < n:
        return 0

    score = 0
    for i in range(len(text) - n + 1):
        ngram = text[i : i + n]
        if ngram in BIGRAMS:
            score += BIGRAMS[ngram]

    return score / len(text)


def kasiski_examination(ciphertext):
    """Kasiski examination for finding Vigenère key length."""
    ciphertext = clean_text(ciphertext)
    min_len = 3
    max_len = 16

    distances = []
    for length in range(min_len, max_len + 1):
        for i in range(len(ciphertext) - 2 * length):
            chunk = ciphertext[i : i + length]
            rest = ciphertext[i + length :]
            if chunk in rest:
                pos1 = i
                pos2 = rest.find(chunk) + i + length
                distances.append((length, pos2 - pos1))

    return distances


def find_vigenere_key_length(ciphertext, max_len=20):
    """Find likely Vigenère key length using IC analysis."""
    ciphertext = clean_text(ciphertext)
    scores = []

    for period in range(2, max_len + 1):
        ic_sum = 0
        for i in range(period):
            subsequence = ciphertext[i::period]
            ic_sum += index_of_coincidence(subsequence)
        avg_ic = ic_sum / period
        scores.append((period, avg_ic))

    return sorted(scores, key=lambda x: -x[1])


def decrypt_with_keylength(ciphertext, key_length):
    """Decrypt Vigenère by finding best key for given length."""
    ciphertext = clean_text(ciphertext)

    key = []
    for i in range(key_length):
        col = ciphertext[i::key_length]

        best_shift = 0
        best_score = -float("inf")

        for shift in range(26):
            decrypted = caesar_decrypt(col, shift)
            score = ngram_score(decrypted)
            if score > best_score:
                best_score = score
                best_shift = shift

        key.append(n2let(best_shift))

    return "".join(key)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def find_key_for_plaintext(cipher: str, plaintext: str) -> str:
    """Derive key needed to transform cipher to plaintext"""
    if len(cipher) != len(plaintext):
        raise ValueError("Cipher and plaintext must be same length")

    key = ""
    for c, p in zip(cipher, plaintext):
        c_idx = ord(c) - ord("A")
        p_idx = ord(p) - ord("A")
        key_idx = (c_idx - p_idx) % 26
        key += chr(key_idx + ord("A"))
    return key


def analyze_ngrams(text: str, n: int = 3) -> Counter:
    """Analyze n-grams in text"""
    ngrams = [text[i : i + n] for i in range(len(text) - n + 1)]
    return Counter(ngrams)


def find_key_pattern(key_needed_at_pos: dict, max_len: int = 30) -> list:
    """Find repeating key pattern from required key positions"""
    patterns = []
    for L in range(1, max_len + 1):
        key_chars = [None] * L
        possible = True

        for pos, needed_char in key_needed_at_pos.items():
            if needed_char:
                pos_in_key = pos % L
                if key_chars[pos_in_key] is None:
                    key_chars[pos_in_key] = needed_char
                elif key_chars[pos_in_key] != needed_char:
                    possible = False
                    break

        if possible and all(k is not None for k in key_chars):
            patterns.append("".join(key_chars))

    return patterns


def brute_force_vigenere(cipher: str, max_key_len: int = 6, min_match: int = 1) -> list:
    """Brute force Vigenère - returns list of (key, matches)"""
    results = []
    for key_len in range(1, max_key_len + 1):
        for key_tuple in itertools.product(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ", repeat=key_len
        ):
            key = "".join(key_tuple)
            pt = vigenere_decrypt(cipher, key)
            results.append((key, pt))
    return results


def search_plaintext(cipher: str, search_term: str, decrypt_func, *args) -> list:
    """Search for term in decrypted text"""
    results = []
    decrypted = decrypt_func(cipher, *args)
    if search_term in decrypted:
        idx = decrypted.index(search_term)
        results.append((idx, decrypted))
    return results


def decode_message(cipher: str, clues: dict, decrypt_func, *args) -> dict:
    """Check if decrypted text matches known clues"""
    result = {"matches": [], "decrypted": decrypt_func(cipher, *args)}
    for name, (start, end) in clues.items():
        if result["decrypted"][start:end] == name:
            result["matches"].append(name)
    return result


# ============================================================================
# GENERIC ENCRYPT/DECRYPT
# ============================================================================


def encrypt(text, cipher_name, key, **kwargs):
    """Generic encrypt function"""
    cipher_funcs = {
        "caesar": lambda: caesar_encrypt(text, key),
        "atbash": lambda: atbash(text),
        "vigenere": lambda: vigenere_encrypt(text, key),
        "beaufort": lambda: beaufort_encrypt(text, key),
        "variant_beaufort": lambda: variant_beaufort_encrypt(text, key),
        "autokey": lambda: autokey_enc(text, key),
        "running_key": lambda: running_key_encrypt(text, key),
        "gronsfeld": lambda: gronsfeld_enc(text, key),
        "columnar": lambda: columnar_enc(text, key),
        "rail_fence": lambda: rail_fence_enc(text, key),
        "scytale": lambda: scytale_enc(text, key),
        "playfair": lambda: playfair_encrypt(text, key),
        "bifid": lambda: bifid_encrypt(text, key, kwargs.get("period", 5)),
        "hill": lambda: hill_enc(text, key),
        "bazeries": lambda: bazeries_dec(text, key),
        "xor": lambda: xor_cipher(text, key),
    }
    return cipher_funcs.get(cipher_name, lambda: text)()


def decrypt(text, cipher_name, key, **kwargs):
    """Generic decrypt function"""
    cipher_funcs = {
        "caesar": lambda: caesar_decrypt(text, key),
        "atbash": lambda: atbash(text),
        "vigenere": lambda: vigenere_decrypt(text, key),
        "beaufort": lambda: beaufort_decrypt(text, key),
        "variant_beaufort": lambda: variant_beaufort_dec(text, key),
        "autokey": lambda: autokey_dec(text, key),
        "running_key": lambda: running_key_decrypt(text, key),
        "gronsfeld": lambda: gronsfeld_dec(text, key),
        "columnar": lambda: columnar_dec(text, key),
        "rail_fence": lambda: rail_fence_dec(text, key),
        "scytale": lambda: scytale_dec(text, key),
        "playfair": lambda: playfair_decrypt(text, key),
        "bifid": lambda: bifid_dec(text, key, kwargs.get("period", 5)),
        "hill": lambda: hill_dec(text, key),
        "bazeries": lambda: bazeries_dec(text, key),
        "xor": lambda: xor_cipher(text, key),
    }
    return cipher_funcs.get(cipher_name, lambda: text)()


# ============================================================================
# EXAMPLE USAGE (for testing only)
# ============================================================================


def _test():
    """Run basic tests."""
    test_plain = "HELLOWORLD"
    test_key = "KEY"

    caesar_result = caesar_encrypt(test_plain, 5)
    assert caesar_decrypt(caesar_result, 5) == test_plain

    vigenere_result = vigenere_encrypt(test_plain, test_key)
    assert vigenere_decrypt(vigenere_result, test_key) == test_plain

    return True
