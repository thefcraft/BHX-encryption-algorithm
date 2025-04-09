from contextlib import contextmanager
from typing import Literal, BinaryIO, Optional, Generator, Union
from io import BufferedWriter, BufferedReader, RawIOBase, SEEK_CUR, SEEK_SET, SEEK_END
from . import BHX

class BHXStreamWriter(RawIOBase):
    def __init__(self, file: BinaryIO, bhx: BHX):
        self._file = file
        self._closed = False
        
        self._bhx = bhx
        self._bhx.reset_stream()
        
        initial_chunk = self._bhx.start_encrypt_stream()
        self._file.write(initial_chunk) # Write IV
    
        self._last_chunk: Optional[bytes] = None
        assert not self._bhx.use_bcrypt and not self._bhx.use_hmac, \
            "use_hmac and use_bcrypt is not support yet for files"
    
    def close(self): 
        if self._last_chunk is not None:
            encrypted_chunk = self._bhx.encrypt_chunk_stream(self._last_chunk)
            self._file.write(encrypted_chunk)
        self._closed = True
        
    def seekable(self) -> bool: return False
    def write(self, data: bytes):
        if self._closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        if self._last_chunk is None and len(data) < 32:
            self._last_chunk = data
            return
        if self._last_chunk is not None and len(self._last_chunk + data) < 32:
            self._last_chunk = self._last_chunk + data
            return 
        if self._last_chunk is not None:
            data = self._last_chunk + data
        # assert len(data) >= 32
        last_i = -1
        for i in range(0, len(data)-32, 32):
            chunk = data[i:i+32]
            encrypted_chunk = self._bhx.encrypt_chunk_stream(chunk)
            self._file.write(encrypted_chunk)
            last_i = i
        if last_i == -1:
            chunk = data[0:32]
            encrypted_chunk = self._bhx.encrypt_chunk_stream(chunk)
            self._file.write(encrypted_chunk)
            self._last_chunk = None
        else:
            if len(data)%32 == 0:
                chunk = data[last_i+32:last_i+64]
                encrypted_chunk = self._bhx.encrypt_chunk_stream(chunk)
                self._file.write(encrypted_chunk)
                self._last_chunk = None
            else:
                chunk = data[last_i+32:last_i+32+len(data)%32]
                self._last_chunk = chunk
        
class BHXStreamReader(RawIOBase):
    def __init__(self, file: BinaryIO, bhx: BHX):
        self._file = file
        self._closed = False
        
        self._bhx = bhx
        self._bhx.reset_stream()
        
        initial_chunk = self._file.read(16) # Read IV
        self._bhx.start_decrypt_stream(initial_chunk)
        
        self._pos: int = 0
        self._last_chunk: Optional[bytes] = None
        assert not self._bhx.use_bcrypt and not self._bhx.use_hmac, \
            "use_hmac and use_bcrypt is not support yet for files"
    
    def close(self): self._closed = True
    def seekable(self) -> bool: return not self._bhx.use_new_key_depends_on_old_key
    def tell(self) -> int: return self._pos
    def seek(self, offset, whence: Literal[0, 1] = 0):
        if not self.seekable():
            raise ValueError("seek is not spported for bhx.use_new_key_depends_on_old_key type of encryption.")
        if whence == SEEK_CUR: 
            offset = self._pos + offset
        self._pos = offset
    def read(self, size: int = -1) -> bytes:
        if self._closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        if self.seekable():
            self._file.seek(16+self._pos - self._pos%32) # 16 for READ_IV
            encrypted_data = self._file.read(size + self._pos%32 if size != -1 else -1)
            decrypted_data = bytearray()
            if self._pos%32 != 0:
                self._bhx.counter = (self._pos - self._pos%32) // 32    
                self._bhx.current_newkey = self._bhx.new_key(self._bhx.key, self._bhx.key, self._bhx.IV, self._bhx.IV, self._bhx.counter)
            if len(encrypted_data) != 0:
                chunk = encrypted_data[:32]
                decrypted_chunk = self._bhx.decrypt_chunk_stream(chunk)
                decrypted_data.extend(decrypted_chunk[self._pos%32:])
            for i in range(32, len(encrypted_data), 32):
                chunk = encrypted_data[i:i+32]
                decrypted_chunk = self._bhx.decrypt_chunk_stream(chunk)
                decrypted_data.extend(decrypted_chunk)
            
            self._pos += len(decrypted_data)
            return bytes(decrypted_data)
        else:
            decrypted_data = bytearray()
            if self._pos%32 != 0:
                assert self._last_chunk is not None, "Something Went Wrong Check the logic again in the BHXStreamReader"
                if size == -1 or size > 32-self._pos%32:
                    decrypted_data.extend(self._last_chunk[self._pos%32:])
                else:
                    decrypted_data.extend(self._last_chunk[self._pos%32:size + self._pos%32])
                    self._pos += len(decrypted_data)
                    return bytes(decrypted_data)
            encrypted_data = self._file.read(size + (32-size%32) if size != -1 and size%32 != 0 else size)
            last_i = -1
            for i in range(0, len(encrypted_data)-32, 32):
                chunk = encrypted_data[i:i+32]
                decrypted_chunk = self._bhx.decrypt_chunk_stream(chunk)
                decrypted_data.extend(decrypted_chunk)
                last_i = i
            if len(encrypted_data) != 0:
                if last_i == -1:
                    chunk = encrypted_data[0:32]
                else:
                    chunk = encrypted_data[last_i+32:last_i+64]
                decrypted_chunk = self._bhx.decrypt_chunk_stream(chunk)
                self._last_chunk = decrypted_chunk
                if size == -1:
                    decrypted_data.extend(decrypted_chunk)
                else:
                    decrypted_data.extend(decrypted_chunk[:size-32+self._pos%32])
            self._pos += len(decrypted_data)
            return bytes(decrypted_data)
        
@contextmanager
def open_bhx_file(file_name: str, mode: Literal['rb', 'wb'], bhx: BHX):
    if 'wb' in mode:
        with open(file_name, mode) as file:
            with BHXStreamWriter(file, bhx) as writer:
                yield writer
    elif 'rb' in mode:
        with open(file_name, mode) as file:
            with BHXStreamReader(file, bhx) as reader:
                yield reader
    else:
        raise ValueError("Mode must be 'rb' or 'wb'")