import unittest
from . import BHX

class TestStream(unittest.TestCase):
    def test_empty_message_stream(self):
        key = b"test key"
        encrypter = BHX(key=key)
        initial_chunk = encrypter.start_encrypt_stream()
        encrypter.reset_stream()
        decrypter = BHX(key=key)
        decrypter.start_decrypt_stream(initial_chunk)
        decrypter.reset_stream()
        self.assertEqual(b'', b'')  # No chunks processed

    def test_short_message_stream(self):
        key = b"test key"
        plaintext = b"Hello"
        encrypter = BHX(key=key)
        initial_chunk = encrypter.start_encrypt_stream()
        encrypted_chunk = encrypter.encrypt_chunk_stream(plaintext)
        encrypter.reset_stream()
        
        decrypter = BHX(key=key)
        decrypter.start_decrypt_stream(initial_chunk)
        decrypted_chunk = decrypter.decrypt_chunk_stream(encrypted_chunk)
        decrypter.reset_stream()
        
        self.assertEqual(plaintext, decrypted_chunk)

    def test_exact_chunk_stream(self):
        key = b"test key"
        plaintext = b"A" * 32
        encrypter = BHX(key=key)
        initial_chunk = encrypter.start_encrypt_stream()
        encrypted_chunk = encrypter.encrypt_chunk_stream(plaintext)
        encrypter.reset_stream()
        decrypter = BHX(key=key)
        decrypter.start_decrypt_stream(initial_chunk)
        decrypted_chunk = decrypter.decrypt_chunk_stream(encrypted_chunk)
        decrypter.reset_stream()
        self.assertEqual(plaintext, decrypted_chunk)

    def test_multiple_chunks_stream(self):
        key = b"test key"
        plaintext = b"A" * 64
        chunks = [plaintext[i:i+32] for i in range(0, 64, 32)]
        encrypter = BHX(key=key)
        initial_chunk = encrypter.start_encrypt_stream()
        encrypted_chunks = [encrypter.encrypt_chunk_stream(chunk) for chunk in chunks]
        encrypter.reset_stream()
        decrypter = BHX(key=key)
        decrypter.start_decrypt_stream(initial_chunk)
        decrypted_chunks = [decrypter.decrypt_chunk_stream(enc_chunk) for enc_chunk in encrypted_chunks]
        decrypter.reset_stream()
        decrypted_data = b''.join(decrypted_chunks)
        self.assertEqual(plaintext, decrypted_data)

    def test_wrong_key_stream(self):
        key = b"test key"
        wrong_key = b"wrong key"
        plaintext = b"Hello"
        encrypter = BHX(key=key)
        initial_chunk = encrypter.start_encrypt_stream()
        encrypter.encrypt_chunk_stream(plaintext)
        encrypter.reset_stream()
        decrypter = BHX(key=wrong_key)
        with self.assertRaises(ValueError):
            decrypter.start_decrypt_stream(initial_chunk)

    def test_stream_not_started(self):
        key = b"test key"
        encrypter = BHX(key=key)
        with self.assertRaises(ValueError):
            encrypter.encrypt_chunk_stream(b"test")
        decrypter = BHX(key=key)
        with self.assertRaises(ValueError):
            decrypter.decrypt_chunk_stream(b"test")

    def test_non_streaming(self):
        key = b"test key"
        plaintext = b"Hello, World!"
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(plaintext)
        decrypter = BHX(key=key)
        decrypted_data = decrypter.decrypt(encrypted_data)
        self.assertEqual(plaintext, decrypted_data)

    def test_non_streaming_wrong_key(self):
        key = b"test key"
        wrong_key = b"wrong key"
        plaintext = b"Hello, World!"
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(plaintext)
        decrypter = BHX(key=wrong_key)
        with self.assertRaises(ValueError):
            decrypter.decrypt(encrypted_data)

    def test_non_streaming_tampered_data(self):
        key = b"test key"
        plaintext = b"Hello, World!"
        encrypter = BHX(key=key)
        encrypted_data = encrypter.encrypt(plaintext)
        tampered_data = encrypted_data[:-32] + b'\x00' * 32  # Replace HMAC
        decrypter = BHX(key=key)
        with self.assertRaises(ValueError):
            decrypter.decrypt(tampered_data)
