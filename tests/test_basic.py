import unittest
from . import BHX

class TestBasic(unittest.TestCase):
    def test_empty_message(self):
        key = b"very safe password" # must be safe
        original_data = b''
        
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(original_data)
        
        decrypter = BHX(key=key)
        decrypted_data = decrypter.decrypt(encrypted_data)        
        self.assertEqual(original_data, decrypted_data)  # No chunks processed
    
    def test_wrong_password(self):
        key = b"very safe password" # must be safe
        original_data = b''
        
        encrypter = BHX(key=key, use_bcrypt=True)
        encrypted_data = encrypter.encrypt(original_data)
        
        try:
            decrypter = BHX(key=b"wrong password", use_bcrypt=True)    
            decrypted_data = decrypter.decrypt(encrypted_data)
        except ValueError as e:
            return
        
        encrypter = BHX(key=key, use_hmac=True)
        encrypted_data = encrypter.encrypt(original_data)
        
        try:
            decrypter = BHX(key=b"wrong password", use_hmac=True)    
            decrypted_data = decrypter.decrypt(encrypted_data)
        except ValueError as e:
            return
        self.fail("Should have raised an exception")
        
    def test_short_message(self):
        key = b"very safe password"
        original_data = b"Hello"
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(original_data)
        
        decrypter = BHX(key=key)
        decrypted_data = decrypter.decrypt(encrypted_data)        
        self.assertEqual(original_data, decrypted_data)
    
    def test_exact_chunk(self):
        key = b"very safe password"
        original_data = b"A" * 32
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(original_data)
        
        decrypter = BHX(key=key)
        decrypted_data = decrypter.decrypt(encrypted_data)        
        self.assertEqual(original_data, decrypted_data)
        
    def test_long_message(self):
        key = b"very safe password"
        original_data = b"Hello, World! This is a test message."*888
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(original_data)
        
        decrypter = BHX(key=key)
        decrypted_data = decrypter.decrypt(encrypted_data)        
        self.assertEqual(original_data, decrypted_data)
    