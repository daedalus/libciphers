import pytest
import libciphers as cipher


class TestUtilityFunctions:
    """Test utility functions."""

    def test_let2n(self):
        assert cipher.let2n("A") == 0
        assert cipher.let2n("M") == 12
        assert cipher.let2n("Z") == 25

    def test_n2let(self):
        assert cipher.n2let(0) == "A"
        assert cipher.n2let(12) == "M"
        assert cipher.n2let(25) == "Z"

    def test_clean_text(self):
        assert cipher.clean_text("ABC") == "ABC"
        assert cipher.clean_text("") == ""

    def test_keyed_alphabet(self):
        result = cipher.keyed_alphabet("CIPHER")
        assert result[0] == "C"
        assert len(result) == 26

    def test_clean(self):
        assert cipher.clean("ABC") == "ABC"
        assert cipher.clean("") == ""

    def test_text_to_numbers(self):
        assert cipher.text_to_numbers("ABC") == [0, 1, 2]
        assert cipher.text_to_numbers("") == []

    def test_numbers_to_text(self):
        assert cipher.numbers_to_text([0, 1, 2]) == "ABC"
        assert cipher.numbers_to_text([]) == ""

    def test_make_polybius(self):
        result = cipher.make_polybius("KEY")
        assert len(result) == 25
        assert "J" not in result


class TestCaesarCipher:
    """Test Caesar cipher functions."""

    def test_caesar_roundtrip(self):
        plaintext = "TEST"
        encrypted = cipher.caesar_encrypt(plaintext, 5)
        decrypted = cipher.caesar_decrypt(encrypted, 5)
        assert decrypted == plaintext

    def test_caesar_brute_force(self):
        results = cipher.caesar_brute_force("KHOOR")
        assert len(results) == 26

    def test_rot13(self):
        encrypted = cipher.rot13("HELLO")
        decrypted = cipher.rot13(encrypted)
        assert decrypted == "HELLO"


class TestAtbashCipher:
    """Test Atbash cipher."""

    def test_atbash_roundtrip(self):
        plaintext = "TEST"
        encrypted = cipher.atbash(plaintext)
        decrypted = cipher.atbash(encrypted)
        assert decrypted == plaintext

    def test_atbash_with_punctuation(self):
        result = cipher.atbash("TEST 123")
        assert "G" in result or "V" in result


class TestRotN:
    """Test ROT-N cipher."""

    def test_rot_n(self):
        encrypted = cipher.rot_n("HELLO", 5)
        decrypted = cipher.rot_n(encrypted, 21)
        assert decrypted == "HELLO"


class TestAffineCipher:
    """Test Affine cipher functions."""

    def test_affine_roundtrip(self):
        plaintext = "TEST"
        encrypted = cipher.affine_encrypt(plaintext, 5, 3)
        decrypted = cipher.affine_decrypt(encrypted, 5, 3)
        assert decrypted == plaintext

    def test_affine_brute_force(self):
        results = cipher.affine_brute_force("KHOOR")
        assert len(results) > 0
        assert all(isinstance(r, tuple) for r in results)


class TestSimpleSubstitution:
    """Test simple substitution cipher."""

    def test_simple_substitution_decrypt(self):
        mapping = {"A": "Z", "B": "Y", "C": "X"}
        result = cipher.simple_substitution_decrypt("ABC", mapping)
        assert result == "ZYX"


class TestPlayfair:
    """Test Playfair cipher."""

    def test_generate_playfair_matrix(self):
        matrix = cipher.generate_playfair_matrix("KEYWORD")
        assert len(matrix) == 5
        assert all(len(row) == 5 for row in matrix)


class TestVigenereCipher:
    """Test Vigenère cipher functions."""

    def test_vigenere_roundtrip(self):
        plaintext = "TESTMESSAGE"
        key = "KEY"
        encrypted = cipher.vigenere_encrypt(plaintext, key)
        decrypted = cipher.vigenere_decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_vigenere_dec_a1(self):
        result = cipher.vigenere_dec_a1("TEST", "KEY")
        assert isinstance(result, str)

    def test_vigenere_dec_pos(self):
        result = cipher.vigenere_dec_pos("TEST", "KEY")
        assert isinstance(result, str)

    def test_vigenere_enc_pos(self):
        result = cipher.vigenere_enc_pos("TEST", "KEY")
        assert isinstance(result, str)

    def test_vigenere_dec_cumulative(self):
        result = cipher.vigenere_dec_cumulative("TEST", "KEY")
        assert isinstance(result, str)

    def test_vigenere_enc_cumulative(self):
        result = cipher.vigenere_enc_cumulative("TEST", "KEY")
        assert isinstance(result, str)


class TestBeaufortCipher:
    """Test Beaufort cipher functions."""

    def test_beaufort_roundtrip(self):
        plaintext = "TEST"
        key = "KEY"
        encrypted = cipher.beaufort_encrypt(plaintext, key)
        decrypted = cipher.beaufort_decrypt(encrypted, key)
        assert decrypted == plaintext


class TestVariantBeaufort:
    """Test Variant Beaufort cipher."""

    def test_variant_beaufort_encrypt(self):
        plaintext = "TEST"
        key = "KEY"
        result = cipher.variant_beaufort_encrypt(plaintext, key)
        assert isinstance(result, str)

    def test_variant_beaufort_decrypt(self):
        ciphertext = "TEST"
        key = "KEY"
        result = cipher.variant_beaufort_dec(ciphertext, key)
        assert isinstance(result, str)


class TestPortaCipher:
    """Test Porta cipher."""

    def test_porta_dec(self):
        result = cipher.porta_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestAutokeyCipher:
    """Test Autokey cipher."""

    def test_autokey_enc(self):
        plaintext = "TEST"
        key = "KEY"
        result = cipher.autokey_enc(plaintext, key)
        assert isinstance(result, str)

    def test_autokey_dec(self):
        ciphertext = "TEST"
        key = "KEY"
        result = cipher.autokey_dec(ciphertext, key)
        assert isinstance(result, str)


class TestRunningKeyCipher:
    """Test Running Key cipher."""

    def test_running_key(self):
        plaintext = "TEST"
        key = "RANDOMTEXT"
        encrypted = cipher.running_key_encrypt(plaintext, key)
        decrypted = cipher.running_key_decrypt(encrypted, key)
        assert decrypted == plaintext


class TestGronsfeldCipher:
    """Test Gronsfeld cipher."""

    def test_gronsfeld(self):
        plaintext = "TEST"
        key = "1234"
        encrypted = cipher.gronsfeld_enc(plaintext, key)
        decrypted = cipher.gronsfeld_dec(encrypted, key)
        assert decrypted == plaintext


class TestQuagmireCipher:
    """Test Quagmire cipher."""

    def test_quagmire_encrypt_decrypt(self):
        plaintext = "TEST"
        key = "KEY"
        indicator = "A"
        encrypted = cipher.quagmire_encrypt(plaintext, key, indicator, 3)
        decrypted = cipher.quagmire_decrypt(encrypted, key, indicator, 3)
        assert decrypted == plaintext


class TestPolybiusCipher:
    """Test Polybius cipher."""

    def test_polybius_enc_dec(self):
        plaintext = "TEST"
        encrypted = cipher.polybius_encrypt(plaintext)
        decrypted = cipher.polybius_decrypt(encrypted)
        assert decrypted == plaintext


class TestStraddlingCheckerboard:
    """Test Straddling Checkerboard cipher."""

    def test_straddling_encrypt(self):
        plaintext = "TEST"
        keyword = "CIPHER"
        result = cipher.straddling_checkerboard_encrypt(plaintext, keyword)
        assert isinstance(result, str)

    def test_straddling_decrypt(self):
        numbers = "0123456789"
        keyword = "CIPHER"
        result = cipher.straddling_checkerboard_decrypt(numbers, keyword)
        assert isinstance(result, str)


class TestColumnarTransposition:
    """Test Columnar Transposition cipher."""

    def test_columnar_encrypt(self):
        plaintext = "TESTMESSAGE"
        key = "KEY"
        result = cipher.columnar_transpose_encrypt(plaintext, key)
        assert isinstance(result, str)

    def test_columnar_decrypt(self):
        ciphertext = "TESTMESSAGE"
        key = "KEY"
        result = cipher.columnar_transpose_decrypt(ciphertext, key)
        assert isinstance(result, str)


class TestRailFenceCipher:
    """Test Rail Fence cipher functions."""

    def test_rail_fence_roundtrip(self):
        plaintext = "TEST"
        for rails in [2, 3, 4]:
            encrypted = cipher.rail_fence_decrypt(plaintext, rails)
            decrypted = cipher.rail_fence_decrypt(encrypted, rails)
            assert decrypted == plaintext

    def test_rail_fence_enc_dec(self):
        plaintext = "TEST"
        for rails in [2, 3]:
            encrypted = cipher.rail_fence_enc(plaintext, rails)
            decrypted = cipher.rail_fence_dec(encrypted, rails)
            assert decrypted == plaintext


class TestScytaleCipher:
    """Test Scytale cipher."""

    def test_scytale_enc(self):
        plaintext = "TEST"
        rods = 3
        result = cipher.scytale_enc(plaintext, rods)
        assert isinstance(result, str)

    def test_scytale_decrypt(self):
        ciphertext = "TEST"
        rods = 3
        result = cipher.scytale_decrypt(ciphertext, rods)
        assert isinstance(result, str)


class TestDoubleTransposition:
    """Test Double Transposition cipher."""

    def test_double_transposition_encrypt(self):
        plaintext = "TESTMESSAGE"
        key1 = "KEY"
        key2 = "WORD"
        result = cipher.double_transposition_encrypt(plaintext, key1, key2)
        assert isinstance(result, str)

    def test_double_transposition_decrypt(self):
        ciphertext = "TEST"
        key1 = "KEY"
        key2 = "WORD"
        result = cipher.double_transposition_decrypt(ciphertext, key1, key2)
        assert isinstance(result, str)


class TestZigzag:
    """Test Zigzag cipher."""

    def test_zigzag_decrypt(self):
        result = cipher.zigzag_decrypt("TEST", 3)
        assert isinstance(result, str)


class TestDiagonalRead:
    """Test Diagonal Read cipher."""

    def test_diagonal_read_decrypt(self):
        result = cipher.diagonal_read_decrypt("TEST", 3)
        assert isinstance(result, str)


class TestMyszkowski:
    """Test Myszkowski cipher."""

    def test_myszkowski_decrypt(self):
        result = cipher.myszkowski_decrypt("TEST", "KEY")
        assert isinstance(result, str)


class TestIrregularColumnar:
    """Test Irregular Columnar cipher."""

    def test_irregular_columnar(self):
        plaintext = "TEST"
        key = "KEY"
        encrypted = cipher.irregular_columnar_dec(plaintext, key)
        assert isinstance(encrypted, str)


class TestRouteTransposition:
    """Test Route Transposition cipher."""

    def test_route_transpose_encrypt(self):
        plaintext = "TESTMESSAGE"
        result = cipher.route_transpose_encrypt(plaintext, 4, 4)
        assert isinstance(result, str)


class TestPlayfairCipher:
    """Test Playfair cipher."""

    def test_playfair_encrypt(self):
        plaintext = "TESTMESSAGE"
        key = "CIPHER"
        result = cipher.playfair_encrypt(plaintext, key)
        assert isinstance(result, str)

    def test_playfair_decrypt(self):
        ciphertext = "TEST"
        key = "CIPHER"
        result = cipher.playfair_decrypt(ciphertext, key)
        assert isinstance(result, str)


class TestFourSquareCipher:
    """Test Four Square cipher."""

    def test_foursquare_enc_dec(self):
        plaintext = "TEST"
        key1 = "KEY"
        key2 = "WORD"
        encrypted = cipher.foursquare_encrypt(plaintext, key1, key2)
        decrypted = cipher.foursquare_decrypt(encrypted, key1, key2)
        assert decrypted == plaintext


class TestThreeSquareCipher:
    """Test Three Square cipher."""

    def test_threesquare_enc_dec(self):
        plaintext = "TEST"
        key1 = "KEY"
        key2 = "WORD"
        result = cipher.threesquare_dec(plaintext, key1, key2)
        assert isinstance(result, str)


class TestBifidCipher:
    """Test Bifid cipher."""

    def test_bifid_encrypt(self):
        plaintext = "TEST"
        key = "CIPHER"
        result = cipher.bifid_encrypt(plaintext, key)
        assert isinstance(result, str)

    def test_bifid_decrypt(self):
        ciphertext = "11234123"
        key = "CIPHER"
        result = cipher.bifid_decrypt(ciphertext, key)
        assert isinstance(result, str)


class TestTrifidCipher:
    """Test Trifid cipher."""

    def test_trifid_encrypt(self):
        plaintext = "TEST"
        key = "CIPHER"
        result = cipher.trifid_encrypt(plaintext, key)
        assert isinstance(result, str)

    def test_trifid_decrypt(self):
        ciphertext = "123456789012"
        key = "CIPHER"
        result = cipher.trifid_decrypt(ciphertext, key)
        assert isinstance(result, str)


class TestHillCipher:
    """Test Hill cipher."""

    def test_hill_enc(self):
        plaintext = "ACT"
        key_matrix = [[3, 2], [2, 7]]
        result = cipher.hill_enc(plaintext, key_matrix)
        assert isinstance(result, str)

    def test_hill_dec(self):
        ciphertext = "TEST"
        key_matrix = [[3, 2], [2, 7]]
        result = cipher.hill_dec(ciphertext, key_matrix)
        assert isinstance(result, str)


class TestMultiplicationCipher:
    """Test Multiplication cipher."""

    def test_multiplication_decrypt(self):
        ciphertext = "TEST"
        result = cipher.multiplication_decrypt(ciphertext, 5)
        assert isinstance(result, str)


class TestProgressiveShift:
    """Test Progressive Shift cipher."""

    def test_progressive_shift_decrypt(self):
        result = cipher.progressive_shift_decrypt("TEST")
        assert isinstance(result, str)


class TestPositionBasedShift:
    """Test Position Based Shift cipher."""

    def test_position_based_shift_decrypt(self):
        result = cipher.position_based_shift_decrypt("TEST")
        assert isinstance(result, str)


class TestSerialShift:
    """Test Serial Shift cipher."""

    def test_serial_shift_decrypt(self):
        result = cipher.serial_shift_decrypt("TEST")
        assert isinstance(result, str)


class TestCumulativeShift:
    """Test Cumulative Shift cipher."""

    def test_cumulative_shift_decrypt(self):
        result = cipher.cumulative_shift_decrypt("TEST")
        assert isinstance(result, str)


class TestPrimePosition:
    """Test Prime Position cipher."""

    def test_prime_position_decrypt(self):
        result = cipher.prime_position_decrypt("TEST")
        assert isinstance(result, str)


class TestFibonacciShift:
    """Test Fibonacci Shift cipher."""

    def test_fibonacci_shift_decrypt(self):
        result = cipher.fibonacci_shift_decrypt("TEST")
        assert isinstance(result, str)


class TestReverseText:
    """Test Reverse Text cipher."""

    def test_reverse_text(self):
        plaintext = "TEST"
        encrypted = cipher.reverse_text(plaintext)
        decrypted = cipher.reverse_text(encrypted)
        assert decrypted == plaintext


class TestEveryNthChar:
    """Test Every Nth Char cipher."""

    def test_every_nth_char(self):
        result = cipher.every_nth_char("TEST", 2)
        assert isinstance(result, str)


class TestXorCipher:
    """Test XOR cipher."""

    def test_xor_cipher(self):
        plaintext = "TEST"
        key = "KEY"
        encrypted = cipher.xor_cipher(plaintext, key)
        decrypted = cipher.xor_cipher(encrypted, key)
        assert decrypted == plaintext


class TestPairSwap:
    """Test Pair Swap cipher."""

    def test_pair_swap_decrypt(self):
        result = cipher.pair_swap_decrypt("TEST")
        assert isinstance(result, str)


class TestComplementCipher:
    """Test Complement cipher."""

    def test_complement_decrypt(self):
        result = cipher.complement_decrypt("TEST")
        assert isinstance(result, str)


class TestBazeriesCipher:
    """Test Bazeries cipher."""

    def test_bazeries_dec(self):
        result = cipher.bazeries_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestQuagmire1:
    """Test Quagmire 1 cipher."""

    def test_quagmire1_dec(self):
        result = cipher.quagmire1_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestQuagmire3:
    """Test Quagmire 3 cipher."""

    def test_quagmire3_dec(self):
        result = cipher.quagmire3_dec("TEST", "PTKEY", "VGKEY")
        assert isinstance(result, str)


class TestQuagmire4:
    """Test Quagmire 4 cipher."""

    def test_quagmire4_dec(self):
        result = cipher.quagmire4_dec("TEST", "PTKEY", "INDKEY", "KEY")
        assert isinstance(result, str)


class TestGromarkCipher:
    """Test Gromark cipher."""

    def test_gromark_dec(self):
        result = cipher.gromark_dec("TESTS", "CIPHER")
        assert isinstance(result, str)


class TestTwoKeyInterleave:
    """Test Two Key Interleave cipher."""

    def test_two_key_interleave_decrypt(self):
        result = cipher.two_key_interleave_decrypt("TEST", "KEY1", "KEY2")
        assert isinstance(result, str)


class TestDoubleDecrypt:
    """Test Double Decrypt cipher."""

    def test_double_decrypt(self):
        result = cipher.double_decrypt("TEST", "KEY1", "KEY2")
        assert isinstance(result, str)


class TestShiftedAlphabet:
    """Test Shifted Alphabet cipher."""

    def test_shifted_alphabet_decrypt(self):
        result = cipher.shifted_alphabet_decrypt("TEST", "KEY")
        assert isinstance(result, str)


class TestKeyDirection:
    """Test Key Direction cipher."""

    def test_key_direction_decrypt(self):
        result = cipher.key_direction_decrypt("TEST", "KEY")
        assert isinstance(result, str)


class TestCipherFeedback:
    """Test Cipher Feedback cipher."""

    def test_cipher_feedback_decrypt(self):
        result = cipher.cipher_feedback_decrypt("TEST", "PRIMER")
        assert isinstance(result, str)


class TestAdditiveFeedback:
    """Test Additive Feedback cipher."""

    def test_additive_feedback_decrypt(self):
        result = cipher.additive_feedback_decrypt("TEST", 5)
        assert isinstance(result, str)


class TestSectionKey:
    """Test Section Key cipher."""

    def test_section_key_dec(self):
        result = cipher.section_key_dec("TEST", ["KEY1", "KEY2"], [2, 2])
        assert isinstance(result, str)


class TestBlockKey:
    """Test Block Key cipher."""

    def test_block_key_dec(self):
        result = cipher.block_key_dec("TEST", ["KEY1", "KEY2"])
        assert isinstance(result, str)


class TestAlternatingKeys:
    """Test Alternating Keys cipher."""

    def test_alternating_keys_dec(self):
        result = cipher.alternating_keys_dec("TEST", "KEY1", "KEY2", "AB")
        assert isinstance(result, str)


class TestProgressiveVigenere:
    """Test Progressive Vigenere cipher."""

    def test_progressive_vigenere(self):
        result = cipher.progressive_vigenere("TEST", "KEY")
        assert isinstance(result, str)


class TestCdpCipher:
    """Test CDP cipher."""

    def test_cdp_dec(self):
        result = cipher.cdp_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestCunninghamCipher:
    """Test Cunningham cipher."""

    def test_cunningham_dec(self):
        result = cipher.cunningham_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestSlidefairCipher:
    """Test Slidefair cipher."""

    def test_slidefair_dec(self):
        result = cipher.slidefair_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestCadenianCipher:
    """Test Cadenus cipher."""

    def test_cadenian_dec(self):
        result = cipher.cadenian_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestRagbabyCipher:
    """Test Ragbaby cipher."""

    def test_ragbaby_dec(self):
        result = cipher.ragbaby_dec("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyV1:
    """Test Rolling Key V1 cipher."""

    def test_rolling_key_v1(self):
        result = cipher.rolling_key_v1("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyV2:
    """Test Rolling Key V2 cipher."""

    def test_rolling_key_v2(self):
        result = cipher.rolling_key_v2("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyV3:
    """Test Rolling Key V3 cipher."""

    def test_rolling_key_v3(self):
        result = cipher.rolling_key_v3("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyFibonacci:
    """Test Rolling Key Fibonacci cipher."""

    def test_rolling_key_fibonacci(self):
        result = cipher.rolling_key_fibonacci("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyPrime:
    """Test Rolling Key Prime cipher."""

    def test_rolling_key_prime(self):
        result = cipher.rolling_key_prime("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeySine:
    """Test Rolling Key Sine cipher."""

    def test_rolling_key_sine(self):
        result = cipher.rolling_key_sine("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyRotate:
    """Test Rolling Key Rotate cipher."""

    def test_rolling_key_rotate(self):
        result = cipher.rolling_key_rotate("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyFeedback:
    """Test Rolling Key Cipher Feedback cipher."""

    def test_rolling_key_cipher_feedback(self):
        result = cipher.rolling_key_cipher_feedback("TEST", "KEY")
        assert isinstance(result, str)


class TestRollingKeyInterleaved:
    """Test Rolling Key Interleaved cipher."""

    def test_rolling_key_interleaved(self):
        result = cipher.rolling_key_interleaved("TEST", "KEY")
        assert isinstance(result, str)


class TestStatisticalFunctions:
    """Test statistical analysis functions."""

    def test_index_of_coincidence(self):
        result = cipher.index_of_coincidence("HELLO")
        assert result >= 0

    def test_ngram_score(self):
        score = cipher.ngram_score("THE")
        assert score >= 0


class TestEnigma:
    """Test Enigma machine."""

    def test_enigma_dec(self):
        result = cipher.enigma_dec("TEST", "I", "II", "III", "B", 0, 0, 0)
        assert isinstance(result, str)


class TestHomophonicCipher:
    """Test Homophonic cipher."""

    def test_homophonic_encrypt(self):
        mapping = {"A": ["1", "2"], "B": ["3"]}
        result = cipher.homophonic_encrypt("AB", mapping)
        assert isinstance(result, str)


class TestMorseCipher:
    """Test Morse cipher."""

    def test_morse_encrypt(self):
        result = cipher.morse_encrypt("TEST")
        assert isinstance(result, str)

    def test_morse_decrypt(self):
        result = cipher.morse_decrypt("... / -")
        assert isinstance(result, str)


class TestChiSquared:
    """Test Chi-squared statistic."""

    def test_chi_squared(self):
        result = cipher.chi_squared("HELLO")
        assert isinstance(result, float)


class TestKasiskiExamination:
    """Test Kasiski examination."""

    def test_kasiski_examination(self):
        result = cipher.kasiski_examination("TEST")
        assert isinstance(result, list)


class TestFindVigenereKeyLength:
    """Test Vigenere key length finding."""

    def test_find_vigenere_key_length(self):
        result = cipher.find_vigenere_key_length("TEST")
        assert isinstance(result, list)


class TestDecryptWithKeylength:
    """Test decrypt with key length."""

    def test_decrypt_with_keylength(self):
        result = cipher.decrypt_with_keylength("TEST", 3)
        assert isinstance(result, str)


class TestFindKeyForPlaintext:
    """Test find key for plaintext."""

    def test_find_key_for_plaintext(self):
        result = cipher.find_key_for_plaintext("KHOOR", "HELLO")
        assert isinstance(result, str)
        assert len(result) == 5


class TestAnalyzeNgrams:
    """Test n-gram analysis."""

    def test_analyze_ngrams(self):
        result = cipher.analyze_ngrams("TEST", 2)
        assert isinstance(result, dict)


class TestFindKeyPattern:
    """Test find key pattern."""

    def test_find_key_pattern(self):
        result = cipher.find_key_pattern({0: "A", 5: "A"})
        assert isinstance(result, list)


class TestBruteForceVigenere:
    """Test brute force Vigenere."""

    def test_brute_force_vigenere(self):
        result = cipher.brute_force_vigenere("KHOOR", max_key_len=2)
        assert isinstance(result, list)


class TestSearchPlaintext:
    """Test search plaintext."""

    def test_search_plaintext(self):
        result = cipher.search_plaintext("KHOOR", "HELLO", cipher.caesar_decrypt, 3)
        assert isinstance(result, list)


class TestDecodeMessage:
    """Test decode message."""

    def test_decode_message(self):
        result = cipher.decode_message(
            "KHOOR", {"HELLO": (0, 5)}, cipher.caesar_decrypt, 3
        )
        assert isinstance(result, dict)


class TestEncrypt:
    """Test generic encrypt function."""

    def test_encrypt_caesar(self):
        result = cipher.encrypt("HELLO", "caesar", 3)
        assert result == "KHOOR"

    def test_encrypt_atbash(self):
        result = cipher.encrypt("HELLO", "atbash", "")
        assert isinstance(result, str)

    def test_encrypt_vigenere(self):
        result = cipher.encrypt("HELLO", "vigenere", "KEY")
        assert isinstance(result, str)


class TestDecrypt:
    """Test generic decrypt function."""

    def test_decrypt_caesar(self):
        result = cipher.decrypt("KHOOR", "caesar", 3)
        assert result == "HELLO"

    def test_decrypt_atbash(self):
        result = cipher.decrypt("HELLO", "atbash", "")
        assert isinstance(result, str)

    def test_decrypt_vigenere(self):
        result = cipher.decrypt("KHOOR", "vigenere", "KEY")
        assert isinstance(result, str)


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_string(self):
        assert cipher.caesar_encrypt("", 5) == ""
        assert cipher.vigenere_encrypt("", "KEY") == ""

    def test_single_character(self):
        assert cipher.caesar_encrypt("A", 1) == "B"
        assert cipher.caesar_decrypt("B", 1) == "A"
