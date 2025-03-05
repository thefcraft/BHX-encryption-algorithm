import secrets
from hashlib import sha256
import hmac
import bcrypt

class BHX:
    def __init__(self, key) -> None:
        self.key = sha256(key).digest()
        # Streaming state variables
        self.is_encrypting = False
        self.is_decrypting = False
        self.current_newkey = None
        self.counter = 0
        self.IV = None

    @classmethod
    def from_random_key(cls, key_len=32):
        return cls(key=secrets.token_bytes(key_len))

    @staticmethod
    def encrypt_chunk(chunk: bytes, key: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(chunk, key))

    @staticmethod
    def new_key(old_key: bytes, initial_key, IV: bytes, data_last: bytes, counter: int) -> bytes:
        return sha256(old_key + initial_key + IV + data_last + counter.to_bytes(4, 'big')).digest()

    def encrypt(self, data: bytes) -> bytearray:
        """Encrypt data and append an HMAC for integrity (non-streaming)."""
        result = bytearray()
        hashed_key = bcrypt.hashpw(sha256(self.key).digest(), bcrypt.gensalt())
        result.extend(hashed_key)  # 60 bytes

        IV = secrets.token_bytes(16)
        initial_chunk = IV
        result.extend(self.encrypt_chunk(initial_chunk, self.key))  # Encrypt IV
        newkey = self.new_key(self.key, self.key, IV, initial_chunk, counter=0)

        for counter, i in enumerate(range(0, len(data), 32), start=1):
            chunk = data[i:i+32]
            result.extend(self.encrypt_chunk(chunk, newkey))
            newkey = self.new_key(newkey, self.key, IV, chunk, counter=counter)

        hmac_value = hmac.new(self.key, result, sha256).digest()
        result.extend(hmac_value)  # Append 32-byte HMAC
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with HMAC verification (non-streaming)."""
        result = bytearray()
        hashed_sha_key, data, received_hmac = data[:60], data[60:-32], data[-32:]
        if not bcrypt.checkpw(sha256(self.key).digest(), hashed_sha_key):
            raise ValueError("Wrong password.")

        initial_chunk = data[:16]
        IV = self.encrypt_chunk(initial_chunk, self.key)
        newkey = self.new_key(self.key, self.key, IV, IV, counter=0)

        computed_hmac = hmac.new(self.key, hashed_sha_key + self.encrypt_chunk(IV, self.key) + data[16:], sha256).digest()
        if not secrets.compare_digest(received_hmac, computed_hmac):
            raise ValueError("HMAC verification failed: Data may have been tampered with.")

        for counter, i in enumerate(range(16, len(data), 32), start=1):
            chunk = data[i:i+32]
            decrypted = self.encrypt_chunk(chunk, newkey)
            result.extend(decrypted)
            newkey = self.new_key(newkey, self.key, IV, decrypted, counter=counter)
        return bytes(result)

    ### Streaming Methods ###
    def start_encrypt_stream(self):
        """Initialize streaming encryption, returning hashed_key and encrypted IV."""
        if self.is_encrypting or self.is_decrypting:
            raise ValueError("Already in a streaming session")
        hashed_key = bcrypt.hashpw(sha256(self.key).digest(), bcrypt.gensalt())
        IV = secrets.token_bytes(16)
        initial_chunk = IV
        initial_chunk = self.encrypt_chunk(initial_chunk, self.key)
        self.IV = IV
        self.counter = 0
        self.current_newkey = self.new_key(self.key, self.key, IV, IV, counter=0)
        self.is_encrypting = True
        return hashed_key + initial_chunk
    
    def encrypt_chunk_stream(self, chunk: bytes) -> bytes:
        """Encrypt a single chunk in streaming mode."""
        if not self.is_encrypting:
            raise ValueError("Encryption stream not started")
        if len(chunk) > 32:
            raise ValueError("Chunk size must be <= 32 bytes")
        self.counter += 1
        encrypted_chunk = self.encrypt_chunk(chunk, self.current_newkey)
        self.current_newkey = self.new_key(self.current_newkey, self.key, self.IV, chunk, counter=self.counter)
        return encrypted_chunk

    def start_decrypt_stream(self, initial_chunk: bytes):
        """Initialize streaming decryption with key verification."""
        if self.is_encrypting or self.is_decrypting:
            raise ValueError("Already in a streaming session")
        hashed_sha_key, initial_chunk = initial_chunk[:60], initial_chunk[60:]
        if not bcrypt.checkpw(sha256(self.key).digest(), hashed_sha_key):
            raise ValueError("Wrong key")
    
        IV = self.encrypt_chunk(initial_chunk, self.key)
        self.IV = IV
        self.counter = 0
        self.current_newkey = self.new_key(self.key, self.key, IV, IV, counter=0)
        self.is_decrypting = True

    def decrypt_chunk_stream(self, chunk: bytes) -> bytes:
        """Decrypt a single chunk in streaming mode."""
        if not self.is_decrypting:
            raise ValueError("Decryption stream not started")
        if len(chunk) > 32:
            raise ValueError("Chunk size must be <= 32 bytes")
        self.counter += 1
        decrypted = self.encrypt_chunk(chunk, self.current_newkey)
        self.current_newkey = self.new_key(self.current_newkey, self.key, self.IV, decrypted, self.counter)
        return decrypted

    def reset_stream(self):
        """Reset streaming state for reuse."""
        self.is_encrypting = False
        self.is_decrypting = False
        self.current_newkey = None
        self.counter = 0
        self.IV = None
    