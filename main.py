from BHX import BHX

# Example usage
if __name__ == "__main__":
    original_data = b"Hello, World! This is a test message."*88
    
    key = b"very safe" # must be safe
    
    # Initialize with a key
    # Encrypt 
    encrypter = BHX(key=key)
    initial_chunk = encrypter.start_encrypt_stream()
    print(initial_chunk)
    chunk1 = encrypter.encrypt_chunk_stream(b"A"*3)
    chunk2 = encrypter.encrypt_chunk_stream(b"A"*3)
    print(chunk1)
    # print(chunk2)
    # Decrypt
    decrypter = BHX(key=key)
    decrypter.start_decrypt_stream(initial_chunk=initial_chunk)
    print(decrypter.decrypt_chunk_stream(chunk1))
    print(decrypter.decrypt_chunk_stream(chunk2))
    
    
    assert decrypter.is_decrypting and encrypter.is_encrypting
    assert decrypter.counter == encrypter.counter
    assert decrypter.IV == encrypter.IV
    assert decrypter.current_newkey == encrypter.current_newkey
    
    
    encrypted_data = encrypter.encrypt(original_data)
    decrypted_data = decrypter.decrypt(encrypted_data)
    # Verify correctness
    assert original_data == decrypted_data
    
    # print(f"Original:  {original_data}")
    # print(f"Encrypted: {encrypted_data}")
    # print(f"Decrypted: {decrypted_data}")

    
    print(f"LEN[{len(original_data)}] original_data : ", original_data[:64])
    print(f"LEN[{len(encrypted_data)}] encrypted_data : ", encrypted_data[:64])
    print(f"LEN[{len(decrypted_data)}] decrypted_data : ", decrypted_data[:64])
    
    