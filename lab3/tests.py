#!/usr/bin/env python3
import unittest
import socket
import threading
import time
import sys
import os
import json
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lab2', 'build', 'Release'))

try:
    import crypto_module
except ImportError:
    sys.exit(1)

from helper import send_msg, recv_msg, b64, unb64
from keyserver import KeyServer

class TestKeyServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.keyserver = KeyServer('localhost', 8000)
        cls.server_thread = threading.Thread(target=cls.keyserver.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)
    
    def test_01_register_client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        
        send_msg(sock, {
            'type': 'register',
            'client_id': 'TestClient1',
            'pubkey': 'test_pubkey_pem_data',
            'p2p_host': 'localhost',
            'p2p_port': 8001
        })
        
        response = recv_msg(sock)
        sock.close()
        
        self.assertEqual(response['status'], 'ok')
        print("Client registration successful")
    
    def test_02_get_client_info(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        
        send_msg(sock, {
            'type': 'register',
            'client_id': 'TestClient2',
            'pubkey': 'test_pubkey_2',
            'p2p_host': 'localhost',
            'p2p_port': 8002
        })
        recv_msg(sock)
        sock.close()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        
        send_msg(sock, {
            'type': 'get',
            'client_id': 'TestClient2'
        })
        
        response = recv_msg(sock)
        sock.close()
        
        self.assertEqual(response['status'], 'ok')
        self.assertEqual(response['pubkey'], 'test_pubkey_2')
        self.assertEqual(response['p2p_port'], 8002)
        print("Client info retrieval successful")
    
    def test_03_get_nonexistent_client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        
        send_msg(sock, {
            'type': 'get',
            'client_id': 'NonExistentClient'
        })
        
        response = recv_msg(sock)
        sock.close()
        
        self.assertEqual(response['status'], 'not_found')
        print("Non-existent client handled correctly")
    
    def test_04_list_clients(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        
        send_msg(sock, {'type': 'list'})
        
        response = recv_msg(sock)
        sock.close()
        
        self.assertEqual(response['status'], 'ok')
        self.assertIsInstance(response['clients'], list)
        self.assertIn('TestClient1', response['clients'])
        self.assertIn('TestClient2', response['clients'])
        print(f"Listed {len(response['clients'])} clients")
    
    def test_05_unregister_client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        
        send_msg(sock, {
            'type': 'unregister',
            'client_id': 'TestClient1'
        })
        
        response = recv_msg(sock)
        sock.close()
        
        self.assertEqual(response['status'], 'ok')
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8000))
        send_msg(sock, {'type': 'get', 'client_id': 'TestClient1'})
        response = recv_msg(sock)
        sock.close()
        
        self.assertEqual(response['status'], 'not_found')
        print("Client unregistration successful")


class TestEncryption(unittest.TestCase):
    def test_01_encrypt_decrypt_cbc(self):
        key = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        plaintext = b"Hello, this is a test message for CBC mode!"
        
        ciphertext = crypto_module.encrypt(
            key=list(key),
            iv=list(iv),
            plaintext=list(plaintext),
            mode="CBC",
            padding="PKCS7"
        )
        
        decrypted = crypto_module.decrypt(
            key=list(key),
            iv=list(iv),
            ciphertext=ciphertext,
            mode="CBC",
            padding="PKCS7"
        )
        
        self.assertEqual(bytes(decrypted), plaintext)
        print("CBC mode encryption/decryption successful")
    
    def test_02_encrypt_decrypt_ecb(self):
        key = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        plaintext = b"Testing ECB mode with the fixed implementation!"
        
        ciphertext = crypto_module.encrypt(
            key=list(key),
            iv=list(iv),
            plaintext=list(plaintext),
            mode="ECB",
            padding="ZERO"
        )
        
        decrypted = crypto_module.decrypt(
            key=list(key),
            iv=list(iv),
            ciphertext=ciphertext,
            mode="ECB",
            padding="ZERO"
        )
        
        self.assertEqual(bytes(decrypted), plaintext)
        print("ECB mode encryption/decryption successful")
    
    def test_04_all_modes(self):
        """Test all cipher modes"""
        modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]
        key = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        plaintext = b"Testing all cipher modes!"
        
        for mode in modes:
            with self.subTest(mode=mode):
                ciphertext = crypto_module.encrypt(
                    key=list(key),
                    iv=list(iv),
                    plaintext=list(plaintext),
                    mode=mode,
                    padding="PKCS7"
                )
                
                decrypted = crypto_module.decrypt(
                    key=list(key),
                    iv=list(iv),
                    ciphertext=ciphertext,
                    mode=mode,
                    padding="PKCS7"
                )
                
                self.assertEqual(bytes(decrypted), plaintext)
                print(f"{mode} mode works correctly")


class TestP2PCommunication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyserver = KeyServer('localhost', 8000)
        cls.server_thread = threading.Thread(target=cls.keyserver.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)
    
    def test_01_rsa_key_generation(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        loaded_public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
        
        self.assertIsNotNone(loaded_public_key)
        print("RSA key generation and serialization successful")
    
    def test_02_hybrid_encryption(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        aes_key = secrets.token_bytes(16)
        aes_iv = secrets.token_bytes(16)
        
        message = "Secret P2P message!"
        ciphertext = crypto_module.encrypt(
            key=list(aes_key),
            iv=list(aes_iv),
            plaintext=list(message.encode('utf-8')),
            mode="CBC",
            padding="PKCS7"
        )
        
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.assertEqual(decrypted_key, aes_key)
        
        plaintext = crypto_module.decrypt(
            key=list(decrypted_key),
            iv=list(aes_iv),
            ciphertext=ciphertext,
            mode="CBC",
            padding="PKCS7"
        )
        
        self.assertEqual(bytes(plaintext).decode('utf-8'), message)
        print("Hybrid encryption (RSA + AES) successful")


class TestEndToEnd(unittest.TestCase):
    
    def test_01_full_message_flow(self):
        alice_private = rsa.generate_private_key(65537, 2048, default_backend())
        alice_public = alice_private.public_key()
        
        bob_private = rsa.generate_private_key(65537, 2048, default_backend())
        bob_public = bob_private.public_key()
        
        message = "Hello Bob, this is Alice!"
        
        aes_key = secrets.token_bytes(16)
        aes_iv = secrets.token_bytes(16)
        
        ciphertext = crypto_module.encrypt(
            key=list(aes_key),
            iv=list(aes_iv),
            plaintext=list(message.encode('utf-8')),
            mode="CBC",
            padding="PKCS7"
        )
        
        encrypted_key = bob_public.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        transmitted_data = {
            'encrypted_key': b64(encrypted_key),
            'iv': b64(aes_iv),
            'ciphertext': b64(bytes(ciphertext))
        }
        
        received_encrypted_key = unb64(transmitted_data['encrypted_key'])
        received_iv = unb64(transmitted_data['iv'])
        received_ciphertext = unb64(transmitted_data['ciphertext'])
        
        decrypted_aes_key = bob_private.decrypt(
            received_encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_message = crypto_module.decrypt(
            key=list(decrypted_aes_key),
            iv=list(received_iv),
            ciphertext=list(received_ciphertext),
            mode="CBC",
            padding="PKCS7"
        )
        
        received_message = bytes(decrypted_message).decode('utf-8')
        
        self.assertEqual(received_message, message)
        print(f"End-to-end message flow successful: '{message}'")


def run_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestKeyServer))
    suite.addTests(loader.loadTestsFromTestCase(TestEncryption))
    suite.addTests(loader.loadTestsFromTestCase(TestP2PCommunication))
    suite.addTests(loader.loadTestsFromTestCase(TestEndToEnd))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)