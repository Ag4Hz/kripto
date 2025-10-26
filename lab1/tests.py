import pytest
import lab1.crypto

def test_caesar_cipher():
    test_data = [
        ("A", "D"),
        ("B", "E"),
        ("I", "L"),
        ("X", "A"),
        ("Z", "C"),
        ("AA", "DD"),
        ("TH", "WK"),
        ("CAT", "FDW"),
        ("DOG", "GRJ"),
        ("TOO", "WRR"),
        ("DAMN", "GDPQ"),
        ("DANIEL", "GDQLHO"),
        ("PYTHON", "SBWKRQ"),
        ("WHEEEEEE", "ZKHHHHHH"),
        ("WITH SPACE", "ZLWK VSDFH"),
        ("WITH TWO SPACES", "ZLWK WZR VSDFHV"),
        ("NUM83R5", "QXP83U5"),
        ("0DD !T$", "0GG !W$")
    ]

    print("Testing caesar cipher for raw text:")
    for plaintext, expected_ciphertext in test_data:
        assert lab1.crypto.encrypt_caesar(plaintext) == expected_ciphertext
    
    print("Testing caesar cipher encryption and decryption for binary files:")
    encrypted = lab1.crypto.encrypt_caesar(open("lab1/cica.png", "rb").read(), binary=True)
    decrypted = lab1.crypto.decrypt_caesar(encrypted, binary=True)
    assert decrypted == open("lab1/cica.png", "rb").read()

def test_vigenere_cipher():
    test_data = [
        ("FLEEATONCE", "A", "FLEEATONCE"),
        ("IMHIT", "H", "PTOPA"),
        ("ATTACKATDAWN", "LEMON", "LXFOPVEFRNHR"),
        ("WEAREDISCOVERED", "LEMON", "HIMFROMEQBGIDSQ"),
        ("WEAREDISCOVERED", "MELON", "IILFRPMDQBHICSQ"),
        ("CANTBELIEVE", "ITSNOTBUTTER", "KTFGPXMCXOI"),
        ("CART", "MAN", "OAEF"),
        ("HYPE", "HYPE", "OWEI"),
        ("SAMELENGTH", "PYTHONISTA", "HYFLZRVYMH"),
        ("SHORTERKEY", "XYZZYZ", "PFNQRDOIDX"),
        ("A", "ONEINPUT", "O"),
    ]

    print("Testing vigenere cipher for raw text:")
    for plaintext, key, expected_ciphertext in test_data:
        assert lab1.crypto.encrypt_vigenere(plaintext, key) == expected_ciphertext

    print("Testing vigenere cipher encryption and decryption for binary files:")
    key = bytes("MYRANDOMKEY", encoding='utf-8')
    encrypted = lab1.crypto.encrypt_vigenere(open("lab1/cica.png", "rb").read(), key, binary=True)
    decrypted = lab1.crypto.decrypt_vigenere(encrypted, key, binary=True)
    assert decrypted == open("lab1/cica.png", "rb").read()

def test_scytale_cipher():
    test_data = [
        ("The quick brown fox jumps over the lazy dog.", 14, "Tnegh r.ef  otqxhu eij culkma pzbsyr  oodwvo")
    ]

    print("Testing scytale cipher for raw text:")
    for plaintext, diameter, expected_ciphertext in test_data:
        assert lab1.crypto.encrypt_scytale(plaintext, diameter) == expected_ciphertext

    print("Testing scytale cipher encryption and decryption for binary files:")
    diameter = 14
    encrypted = lab1.crypto.encrypt_scytale(open("lab1/cica.png", "rb").read(), diameter, binary=True)
    decrypted = lab1.crypto.decrypt_scytale(encrypted, diameter, binary=True)
    assert decrypted == open("lab1/cica.png", "rb").read()

def test_railfence_cipher():
    test_data = [
        ("The quick brown fox jumps over the lazy dog.", 3, "Tqkofjsehadh uc rw o up vrtelz o.eibnxmo  yg"),
    ]

    print("Testing rail fence cipher for raw text:")
    for plaintext, rails, expected_ciphertext in test_data:
        assert lab1.crypto.encrypt_railfence(plaintext, rails) == expected_ciphertext

    print("Testing rail fence cipher encryption and decryption for binary files:")
    rails = 3
    encrypted = lab1.crypto.encrypt_railfence(open("lab1/cica.png", "rb").read(), rails, binary=True)
    decrypted = lab1.crypto.decrypt_railfence(encrypted, rails, binary=True)
    assert decrypted == open("lab1/cica.png", "rb").read()