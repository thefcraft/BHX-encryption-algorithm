import secrets
# import struct
from hashlib import sha256, pbkdf2_hmac
import hmac
import bcrypt 
# from itertools import cycle
# from tqdm import tqdm

class BHX:
    def __init__(self, key) -> None:
        # self.key = key
        self.key = key
        
    @classmethod
    def from_random_key(cls, key_len=32):
        return cls(key = secrets.token_bytes(key_len))
    
    @staticmethod
    def encrypt_chunk(chunk: bytes, key: bytes) -> bytes:
        # return bytes(a ^ b for a, b in zip(chunk, cycle(key)))
        return bytes(a ^ b for a, b in zip(chunk, key))
    
    @staticmethod
    def new_key(old_key: bytes, initial_key, IV: bytes, data_last: bytes, counter: int) -> bytes:
        return sha256(old_key + initial_key + IV + data_last + counter.to_bytes(4, 'big')).digest()
    
    def encrypt(self, data: bytes) -> bytearray:
        """Encrypt data and append an HMAC for integrity."""
        result = bytearray()
        hashed_key = bcrypt.hashpw(sha256(self.key).digest(), bcrypt.gensalt()) 
        result.extend(hashed_key) # 60 bytes
        
        # Generate a random 16-byte IV
        IV = secrets.token_bytes(16)
        initial_chunk = IV
        result.extend(self.encrypt_chunk(initial_chunk, self.key)) # start with IV
        newkey = self.new_key(self.key, self.key, IV, initial_chunk, counter=0)
        
        # Process the rest of the data in chunks of 32 bytes
        for counter, i in enumerate(range(0, len(data), 32), start=1):
            chunk = data[i:i+32]  # len(32) .. sha256
            result.extend(self.encrypt_chunk(chunk, newkey))
            newkey = self.new_key(newkey, self.key, IV, chunk, counter=counter)
            
        # Compute HMAC over IV + ciphertext
        hmac_value = hmac.new(self.key, result, sha256).digest() # result with IV
        result.extend(hmac_value)  # Append 32-byte HMAC
        
        return bytes(result)
    
    def decrypt(self, data: bytes) -> bytes:
        result = bytearray()
        # Extract HMAC (last 32 bytes)
        hashed_sha_key, data, received_hmac = data[:60], data[60:-32], data[-32:]
        if not bcrypt.checkpw(sha256(self.key).digest(), hashed_sha_key):
            raise ValueError("Wrong password.")
        
        # Process the initial chunk separately
        initial_chunk = data[:16]
        IV = self.encrypt_chunk(initial_chunk, self.key)
        newkey = self.new_key(self.key, self.key, IV, IV, counter=0)
        
        # Recompute HMAC and Verify HMAC
        computed_hmac = hmac.new(self.key, hashed_sha_key + self.encrypt_chunk(IV, self.key) + data[16:], sha256).digest()
        if not secrets.compare_digest(received_hmac, computed_hmac):
            raise ValueError("HMAC verification failed: Data may have been tampered with.")

        # Process the rest of the data in chunks of 32 bytes
        for counter, i in enumerate(range(16, len(data), 32), start=1):
            chunk = data[i:i+32]
            decrypted = self.encrypt_chunk(chunk, newkey)
            result.extend(decrypted)
            newkey = self.new_key(newkey, self.key, IV, decrypted, counter=counter)
        return bytes(result)
    
# Example usage
if __name__ == "__main__":
    original_data = b"Hello, World! This is a test message."*88
    
    key = b"very safe password" # must be safe
    
    # Initialize with a key
    encrypter = BHX(key=key)
    # Encrypt 
    encrypted_data = encrypter.encrypt(original_data)
    # Decrypt
    key = b"very safe password" # must be safe
    decrypter = BHX(key=key)
    decrypted_data = decrypter.decrypt(encrypted_data)
    
    # Verify correctness
    # assert original_data == decrypted_data
    
    # print(f"Original:  {original_data}")
    # print(f"Encrypted: {encrypted_data}")
    # print(f"Decrypted: {decrypted_data}")

    
    print(f"LEN[{len(original_data)}] original_data : ", original_data[:64])
    print(f"LEN[{len(encrypted_data)}] encrypted_data : ", encrypted_data[:64])
    print(f"LEN[{len(decrypted_data)}] decrypted_data : ", decrypted_data[:64])
    
    