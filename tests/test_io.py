import unittest
from . import BHX, BHXStreamWriter, BHXStreamReader, BHXBytesIOReader

from io import BytesIO, SEEK_CUR, SEEK_END, SEEK_SET
import random

class TestBHXio(unittest.TestCase):
    def test_basic(self):
        key = b"test key"
        encrypter = BHX(key=key, use_new_key_depends_on_old_key=True, use_bcrypt=False, use_hmac=False)   
        fe = BytesIO()
        
        original_data = b'hello'
        with BHXStreamWriter(fe, bhx=encrypter) as fw: # note: close is required to save the buffer from memory
            fw.write(original_data)
        
        fe.seek(0)
        
        decrypter = BHX(key=key, use_new_key_depends_on_old_key=True)   
        with BHXStreamReader(fe, bhx=decrypter) as fr:
            decrypted_data = fr.read()
            self.assertEqual(original_data, decrypted_data)  # No chunks processed
    def test_long(self):
        key = b"test key"
        encrypter = BHX(key=key, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)   
        fe = BytesIO()
        
        original_data = b'hello'*999
        with BHXStreamWriter(fe, bhx=encrypter) as fw: # note: close is required to save the buffer from memory
            fw.write(original_data)
        
        fe.seek(0)
        
        decrypter = BHX(key=key, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)   
        with BHXStreamReader(fe, bhx=decrypter) as fr:
            decrypted_data = fr.read()
            fr.seek(-24, SEEK_CUR)
            decrypted_data = decrypted_data[:-24] + fr.read()
            self.assertEqual(original_data, decrypted_data)  # No chunks processed
    
    def test_bytes_io(self):
        key = b"test key"
        encrypter = BHX(key=key, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)   
        fe = BytesIO()
        
        original_data = b'hello'*999
        with BHXStreamWriter(fe, bhx=encrypter) as fw: # note: close is required to save the buffer from memory
            fw.write(original_data)
        
        fe.seek(0)
        
        decrypter = BHX(key=key, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)   
        with BHXBytesIOReader(fe, bhx=decrypter) as fr:
            decrypted_data = fr.read()
            fr.seek(-24, SEEK_CUR)
            decrypted_data = decrypted_data[:-24] + fr.read()
            self.assertEqual(original_data, decrypted_data)  # No chunks processed
            self.assertEqual(isinstance(fr, BytesIO), True)
            self.assertEqual(fr.getbuffer().nbytes, len(decrypted_data))
        
        total_size = len(original_data)
        fe.seek(0)
        with BHXBytesIOReader(fe, bhx=decrypter) as fr:
            decrypted_data = b''
            remaning = total_size
            while remaning > 0:
                size = random.randint(0, remaning)
                decrypted_data += fr.read(size)
                remaning -= size
                self.assertEqual(original_data[:len(decrypted_data)], decrypted_data)
        
        # --- Test seek to start and end ---
        fe.seek(0)
        decrypter3 = BHX(key=key, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
        with BHXBytesIOReader(fe, bhx=decrypter3) as fr:
            fr.seek(0, SEEK_END)
            self.assertEqual(fr.tell(), len(original_data))

            fr.seek(0)
            head = fr.read(100)
            self.assertEqual(head, original_data[:100])

            fr.seek(500)
            mid = fr.read(50)
            self.assertEqual(mid, original_data[500:550])
            
            mid = fr.read(50)
            self.assertEqual(mid, original_data[550:600])
            
            fr.seek(500)
            mid = fr.read(50)
            self.assertEqual(mid, original_data[500:550])
            
            mid = fr.read(50)
            self.assertEqual(mid, original_data[550:600])

            fr.seek(-100, SEEK_END)
            tail = fr.read(100)
            self.assertEqual(tail, original_data[-100:])
            
            fr.seek(128)
            mid = fr.read(16)
            self.assertEqual(mid, original_data[128:128+16])
            
            fr.seek(2976)
            mid = fr.read(1674)
            self.assertEqual(mid, original_data[2976:2976+1674])
        
            for _ in range(100):
                start = random.randint(0, total_size-1)
                end = random.randint(0, total_size-1 - start)
                fr.seek(start)
                mid = fr.read(end)
                assert mid == original_data[start:start + end], f'{start}:{end}'
                