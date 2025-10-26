#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import math
import utils
from itertools import cycle, islice

# Wrapper function for encrypting/decrypting binary files
def binary():
    """Encrypt or decrypt a binary file using a Caesar cipher.
    """
    print("Enter input filename:")
    filename = input().strip()
    with open(filename, 'rb') as f:
        data = f.read()

        print("Do you want to (E)ncrypt or (D)ecrypt?")

        choice = input().strip().upper()
        while choice not in ['E', 'D']:
            choice = input("Please enter either 'E' or 'D': ").strip().upper()

        if choice == 'E':
            print("Which encryption tool do you want to use? (C)aesar, (V)igenere, (S)cytale or (R)ail-fence?")
            tool = input().strip().upper()
            while tool not in ['C', 'V', 'S', 'R']:
                tool = input("Please enter either 'C', 'V', 'S' or 'R': ").strip().upper()
            
            if tool == 'C':
                output = encrypt_caesar(data, binary=True)
            if tool == 'V':
                print("Enter keyword as raw text:")
                keyword = input().strip()
                key_bytes = bytes(keyword, encoding='utf8')
                output = encrypt_vigenere(data, key_bytes, binary=True)
            if tool == 'S':
                print("Enter diameter as an integer:")
                diameter = int(input().strip())
                output = encrypt_scytale(data, diameter, binary=True)
            if tool == 'R':
                print("Enter number of rails as an integer:")
                rails = int(input().strip())
                output = encrypt_railfence(data, rails, binary=True)
        else:
            print("Which decryption tool do you want to use? (C)aesar, (V)igenere, (S)cytale or (R)ail-fence?")
            tool = input().strip().upper()
            while tool not in ['C', 'V', 'S', 'R']:
                tool = input("Please enter either 'C', 'V', 'S' or 'R': ").strip().upper()
            
            if tool == 'C':
                output = decrypt_caesar(data, binary=True)
            if tool == 'V':
                print("Enter keyword as raw text:")
                keyword = input().strip()
                key_bytes = bytes(keyword, encoding='utf8')
                output = decrypt_vigenere(data, key_bytes, binary=True)
            if tool == 'S':
                print("Enter diameter as an integer:")
                diameter = int(input().strip())
                output = decrypt_scytale(data, diameter, binary=True)
            if tool == 'R':
                print("Enter number of rails as an integer:")
                rails = int(input().strip())
                output = decrypt_railfence(data, rails, binary=True)

        print("Enter output filename:")
        output_filename = input().strip()
        with open(output_filename, 'wb') as f:
            f.write(output)

# Caesar Cipher

def encrypt_caesar(plaintext, offset = 3, binary=False):
    """Encrypt plaintext or file using a Caesar cipher.
    """
    if binary:
        alphabet_len = 256

        # Split string into a character list
        letters = list(plaintext)
        for i, letter in enumerate(letters):
                letters[i] = (letter + offset) % alphabet_len

        cipherfile = bytes(letters)
        return cipherfile
    else:
        alphabet_len = 26

        # Split string into a character list
        letters = list(plaintext)
        for i, letter in enumerate(letters):
            if not letter.isalpha():
                continue

            if letter.isupper():
                base = ord('A')
                letters[i] = chr(base + (ord(letter) - base + offset) % alphabet_len)
            else:
                base = ord('a')
                letters[i] = chr(base + (ord(letter) - base + offset) % alphabet_len)

        ciphertext = ''.join(letters)
        return ciphertext


def decrypt_caesar(ciphertext, offset = 3, binary=False):
    """Decrypt a ciphertext or file using a Caesar cipher.
    """
    # Decrypting is same as encrypting with an offset of -3 instead of +3
    if binary:
        plainfile = encrypt_caesar(ciphertext, -offset, binary=True)
        return plainfile
    else:
        plaintext = encrypt_caesar(ciphertext, -offset)
        return plaintext


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword, sign = 'positive', binary=False):
    """Encrypt plaintext or file using a Vigenere cipher with a keyword.
    """
    if binary:
        alphabet_len = 256
        plaintext = list(plaintext)
        keyword = list(keyword)
        key = list(islice(cycle(keyword), len(plaintext)))
        if sign == 'negative':
            s = -1
        else:
            s = 1

        for i, byte in enumerate(plaintext):
            plaintext[i] = (byte + s * key[i]) % alphabet_len

        ciphertext = bytes(plaintext)
        return ciphertext
    else:
        alphabet_len = 26

        # Build the key which is the characters of the keyword repeated for the length of the plaintext
        key = list(islice(cycle(keyword), len(plaintext)))
        keyword = keyword.upper() # safety
        
        letters = list(plaintext)
        for i, letter in enumerate(letters):
            if not letter.isalpha():
                continue

            if letter.islower():
                base = ord('a')
                k = ord(key[i]) - base
                offset = k if sign == 'positive' else -k

                letters[i] = chr(base + (ord(letter) - base + offset) % alphabet_len)
            else:
                base = ord('A')
                k = ord(key[i]) - base
                offset = k if sign == 'positive' else -k
                
                letters[i] = chr(base + (ord(letter) - base + offset) % alphabet_len)

        ciphertext = ''.join(letters)
        return ciphertext


def decrypt_vigenere(ciphertext, keyword, binary=False):
    """Decrypt ciphertext or file using a Vigenere cipher with a keyword.
    """
    # Same as with Caesar
    if binary:
        plaintext = encrypt_vigenere(ciphertext, keyword, 'negative', binary=True)
        return plaintext
    else:
        plaintext = encrypt_vigenere(ciphertext, keyword, 'negative')
        return plaintext

# Scytale Cipher

def encrypt_scytale(plaintext, diameter, binary=False):
    """Encrypt plaintext or file using a Scytale cipher with a given diameter.
    """
    if binary:
        n = len(plaintext)
        if n == 0:
            return b""
        cols = diameter
        rows = math.ceil(n / cols)
        rem = n % cols
        full_cols = rem if rem != 0 else cols  # first full_cols columns have 'rows' items

        cipherfile = bytearray(n)
        k = 0
        for c in range(cols):
            col_height = rows if c < full_cols else rows - 1
            for r in range(col_height):
                idx = r * cols + c  # row-major index in original
                cipherfile[k] = plaintext[idx]
                k += 1
        return bytes(cipherfile)
    else:
        # Remove whitespace and punctuation
        plaintext = ''.join(plaintext.split())
        # Pad the plaintext to fit the diameter
        while len(plaintext) % diameter != 0:
            plaintext += 'X'
        # Create the ciphertext by reading the columns
        ciphertext = ''
        for i in range(diameter):
            for j in range(len(plaintext) // diameter):
                ciphertext += plaintext[j * diameter + i]
        return ciphertext


def decrypt_scytale(ciphertext, diameter, binary=False):
    """Decrypt ciphertext or file using a Scytale cipher with a given diameter.
    """
    if binary:
        n = len(ciphertext)
        if n == 0:
            return b""
        cols = diameter
        rows = math.ceil(n / cols)
        rem = n % cols
        full_cols = rem if rem != 0 else cols  # first full_cols columns have 'rows' items

        plainfile = bytearray(n)
        k = 0
        for c in range(cols):
            col_height = rows if c < full_cols else rows - 1
            for r in range(col_height):
                idx = r * cols + c  # row-major index in original
                plainfile[idx] = ciphertext[k]
                k += 1
        return bytes(plainfile)
    else:
        # Create the plaintext by reading the rows
        plaintext = ''
        rows = len(ciphertext) // diameter
        for i in range(rows):
            for j in range(diameter):
                plaintext += ciphertext[j * rows + i]
        return plaintext
    
def encrypt_railfence(plaintext, rails, binary=False):
    """Encrypt plaintext or file using a Rail-fence cipher with a given number of rails.
    """
    if binary:
        n = len(plaintext)
        if n == 0:
            return b""
        # Create the rail fence
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for byte in plaintext:
            fence[rail].append(byte)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        # Read off the rails
        cipherfile = bytearray()
        for row in fence:
            cipherfile.extend(row)
        return bytes(cipherfile)
    else:
        # Remove whitespace and punctuation
        plaintext = ''.join(plaintext.split())
        # Create the rail fence
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for char in plaintext:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        # Read off the rails
        ciphertext = ''.join(''.join(row) for row in fence)
        return ciphertext
    
def decrypt_railfence(ciphertext, rails, binary=False):
    """Decrypt ciphertext or file using a Rail-fence cipher with a given number of rails.
    """
    if binary:
        n = len(ciphertext)
        if n == 0:
            return b""
        # Create the rail fence pattern
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for i in range(n):
            fence[rail].append(None)  # Placeholder
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        # Fill the rails with ciphertext
        index = 0
        for r in range(rails):
            for i in range(len(fence[r])):
                fence[r][i] = ciphertext[index]
                index += 1
        # Read off the rails in zig-zag order
        plainfile = bytearray()
        rail = 0
        direction = 1
        rail_indices = [0] * rails
        for i in range(n):
            plainfile.append(fence[rail][rail_indices[rail]])
            rail_indices[rail] += 1
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        return bytes(plainfile)
    else:
        # Create the rail fence pattern
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for i in range(len(ciphertext)):
            fence[rail].append(None)  # Placeholder
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        # Fill the rails with ciphertext
        index = 0
        for r in range(rails):
            for i in range(len(fence[r])):
                fence[r][i] = ciphertext[index]
                index += 1
        # Read off the rails in zig-zag order
        plaintext = ''
        rail = 0
        direction = 1
        rail_indices = [0] * rails
        for i in range(len(ciphertext)):
            plaintext += fence[rail][rail_indices[rail]]
            rail_indices[rail] += 1
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        return plaintext

# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

