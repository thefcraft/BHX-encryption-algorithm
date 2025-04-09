import unittest
from . import BHX, BHXStreamWriter, BHXStreamReader

from io import BytesIO

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
            fr.seek(-24, 1)
            decrypted_data = decrypted_data[:-24] + fr.read()
            self.assertEqual(original_data, decrypted_data)  # No chunks processed
        