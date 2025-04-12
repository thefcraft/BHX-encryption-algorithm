import unittest
from . import BHX, BHXStreamWriter, BHXStreamReader, BHXBytesIOReader, BHXByteIO  

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
        with BHXBytesIOReader(fe, bhx=decrypter) as fr:
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

class TestBHXBytesIO(unittest.TestCase):
    @staticmethod
    def simulate_writes(ops, initial_size=0):
        buf = bytearray(b'\x00' * initial_size)
        for pos, data in ops:
            end_pos = pos + len(data)
            if end_pos > len(buf):
                buf.extend(b'\x00' * (end_pos - len(buf)))
            buf[pos:end_pos] = data
        return bytes(buf)
    
    def setUp(self):
        self.key = b'safe key'
        self.bhx = BHX(key=self.key, use_new_key_depends_on_old_key=False)

    def test_basic_round_trip(self):
        original = b"The quick brown fox jumps over the lazy dog."
        with BytesIO() as stream:
            with BHXByteIO(stream, bhx=self.bhx) as f:
                f.write(original)
                f.seek(0)
                read = f.read()
        self.assertEqual(read, original)

    def test_seek_and_partial_overwrite(self):
        with BytesIO() as stream:
            with BHXByteIO(stream, bhx=self.bhx) as f:
                f.write(b"abcdefghij")   # Write 10 bytes
                f.seek(3)
                f.write(b"XYZ")         # Overwrite 'def' with 'XYZ'
                f.seek(0)
                result = f.read()
        self.assertEqual(result, b"abcXYZghij")

    def test_multiple_seeks_and_writes(self):
        with BytesIO() as stream:
            with BHXByteIO(stream, bhx=self.bhx) as f:
                f.write(b"Start-")
                f.seek(6)
                f.write(b"Middle-")
                f.seek(0, 2)  # Seek to end
                f.write(b"End")
                f.seek(0)
                result = f.read()
        self.assertEqual(result, b"Start-Middle-End")

    def test_random_access_writes(self):
        random.seed(42)
        ops = []
        for _ in range(10):
            pos = random.randint(0, 100)
            data = bytes(random.getrandbits(8) for _ in range(random.randint(4, 12)))
            ops.append((pos, data))
        expected = self.simulate_writes(ops)
        with BytesIO() as stream:
            with BHXByteIO(stream, bhx=self.bhx) as f:
                for pos, data in ops:
                    f.seek(pos)
                    f.write(data)
                f.seek(0)
                result = f.read()
        self.assertEqual(result, expected)

    def test_no_write(self):
        with BytesIO() as stream:
            with BHXByteIO(stream, bhx=self.bhx):
                pass  # No writes
            stream.seek(0)
            with BHXByteIO(stream, bhx=self.bhx) as f:
                data = f.read()
        self.assertEqual(data, b"")

    def test_write_past_end(self):
        with BytesIO() as stream:
            with BHXByteIO(stream, bhx=self.bhx) as f:
                f.seek(10)  # Seek beyond start
                f.write(b"xyz")
                f.seek(0)
                result = f.read()
        self.assertEqual(result, b"\x00" * 10 + b"xyz")

