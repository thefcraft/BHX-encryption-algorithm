import secrets
from hashlib import sha256
import hmac
import bcrypt
from typing import Optional, Union
from itertools import cycle, islice

# TODO: for the config i mean use_bcrypt and use_hmac etc we can use first few bits to store flags 
class BHX:
    def __init__(self, key, use_bcrypt: bool = False, use_hmac: bool = False, use_new_key_depends_on_old_key: bool = True) -> None:
        self.key = sha256(key).digest()
        # Streaming state variables
        self.is_encrypting = False
        self.is_decrypting = False
        self.current_newkey = None
        self.counter = 0
        self.IV = None

        self.use_bcrypt = use_bcrypt # first 60 bytes used to store bcrypt hashed password
        self.use_hmac = use_hmac # last 32 byte for store hmac [NOTE that it is not used in the stream mode]
        self.use_new_key_depends_on_old_key = use_new_key_depends_on_old_key # if false then seeking left and right is possible and initial key is only required to decrypt the data if we know the counter

    @classmethod
    def from_random_key(cls, key_len=32):
        return cls(key=secrets.token_bytes(key_len))

    @staticmethod
    def encrypt_chunk(chunk: bytes, key: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(chunk, key))

    @staticmethod
    def new_key(old_key: bytes, initial_key, IV: bytes, data_last: bytes, counter: int) -> bytes:
        return sha256(old_key + initial_key + IV + data_last + counter.to_bytes(4, 'big')).digest()

    def encrypt(self, data: bytes, use_iv: bytes = ...) -> bytearray:
        """Encrypt data and append an HMAC for integrity (non-streaming)."""
        result = bytearray()
        if self.use_bcrypt:
            hashed_key = bcrypt.hashpw(sha256(self.key).digest(), bcrypt.gensalt())
            result.extend(hashed_key)  # 60 bytes
        if use_iv == Ellipsis:
            IV = secrets.token_bytes(16)
        else:
            IV = bytes(islice(cycle(use_iv), 16))
        initial_chunk = IV
        result.extend(self.encrypt_chunk(initial_chunk, self.key))  # Encrypt IV
        newkey = self.new_key(self.key, self.key, IV, initial_chunk, counter=0)

        for counter, i in enumerate(range(0, len(data), 32), start=1):
            chunk = data[i:i+32]
            result.extend(self.encrypt_chunk(chunk, newkey))
            if self.use_new_key_depends_on_old_key:
                newkey = self.new_key(newkey, self.key, IV, chunk, counter=counter)
            else:
                newkey = self.new_key(self.key, self.key, IV, IV, counter=counter)

        if self.use_hmac:
            hmac_value = hmac.new(self.key, result, sha256).digest()
            result.extend(hmac_value)  # Append 32-byte HMAC
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with HMAC verification (non-streaming)."""
        result = bytearray()
        if self.use_bcrypt and self.use_hmac:
            hashed_sha_key, data, received_hmac = data[:60], data[60:-32], data[-32:]
            if not bcrypt.checkpw(sha256(self.key).digest(), hashed_sha_key):
                raise ValueError("Wrong password.")
        elif self.use_bcrypt and not self.use_hmac:
            hashed_sha_key, data = data[:60], data[60:]
            if not bcrypt.checkpw(sha256(self.key).digest(), hashed_sha_key):
                raise ValueError("Wrong password.")
        elif not self.use_bcrypt and self.use_hmac:
            data, received_hmac = data[:-32], data[-32:]

        initial_chunk = data[:16]
        IV = self.encrypt_chunk(initial_chunk, self.key)
        newkey = self.new_key(self.key, self.key, IV, IV, counter=0)

        if self.use_hmac:
            if self.use_bcrypt:
                computed_hmac = hmac.new(self.key, hashed_sha_key + self.encrypt_chunk(IV, self.key) + data[16:], sha256).digest()
            else:
                computed_hmac = hmac.new(self.key, self.encrypt_chunk(IV, self.key) + data[16:], sha256).digest()
            if not secrets.compare_digest(received_hmac, computed_hmac):
                raise ValueError("HMAC verification failed: Data may have been tampered with.")

        for counter, i in enumerate(range(16, len(data), 32), start=1):
            chunk = data[i:i+32]
            decrypted = self.encrypt_chunk(chunk, newkey)
            result.extend(decrypted)
            if self.use_new_key_depends_on_old_key:
                newkey = self.new_key(newkey, self.key, IV, decrypted, counter=counter)
            else:
                newkey = self.new_key(self.key, self.key, IV, IV, counter=counter)
        return bytes(result)

    ### Streaming Methods ###
    def start_encrypt_stream(self):
        """Initialize streaming encryption, returning hashed_key and encrypted IV."""
        if self.is_encrypting or self.is_decrypting:
            raise ValueError("Already in a streaming session")
        if self.use_bcrypt:
            hashed_key = bcrypt.hashpw(sha256(self.key).digest(), bcrypt.gensalt())
        IV = secrets.token_bytes(16)
        initial_chunk = IV
        initial_chunk = self.encrypt_chunk(initial_chunk, self.key)
        self.IV = IV
        self.counter = 0
        self.current_newkey = self.new_key(self.key, self.key, IV, IV, counter=0)
        self.is_encrypting = True
        if self.use_bcrypt:
            return hashed_key + initial_chunk
        return initial_chunk
    
    def encrypt_chunk_stream(self, chunk: bytes) -> bytes:
        """Encrypt a single chunk in streaming mode."""
        if not self.is_encrypting:
            raise ValueError("Encryption stream not started")
        if len(chunk) > 32:
            raise ValueError("Chunk size must be <= 32 bytes")
        self.counter += 1
        encrypted_chunk = self.encrypt_chunk(chunk, self.current_newkey)
        if self.use_new_key_depends_on_old_key:
            self.current_newkey = self.new_key(self.current_newkey, self.key, self.IV, chunk, counter=self.counter)
        else:
            self.current_newkey = self.new_key(self.key, self.key, self.IV, self.IV, counter=self.counter)
        return encrypted_chunk

    def start_decrypt_stream(self, initial_chunk: bytes):
        """Initialize streaming decryption with key verification."""
        if self.is_encrypting or self.is_decrypting:
            raise ValueError("Already in a streaming session")
        if self.use_bcrypt: # BTW We can check this based on initial chunk size
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
        if self.use_new_key_depends_on_old_key:
            self.current_newkey = self.new_key(self.current_newkey, self.key, self.IV, decrypted, self.counter)
        else:
            self.current_newkey = self.new_key(self.key, self.key, self.IV, self.IV, self.counter)
        return decrypted

    def reset_stream(self):
        """Reset streaming state for reuse."""
        self.is_encrypting = False
        self.is_decrypting = False
        self.current_newkey = None
        self.counter = 0
        self.IV = None

