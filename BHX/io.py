from contextlib import contextmanager
from typing import Literal, BinaryIO, Optional, Generator, Union, Any
from io import BufferedWriter, BufferedReader, RawIOBase, SEEK_CUR, SEEK_SET, SEEK_END, BytesIO
from .bhx import BHX

# ========================================================================
# Write not seekable
# ========================================================================
class BHXStreamWriter(RawIOBase):
    def __init__(self, file: BinaryIO, bhx: BHX, close_file_on_close: bool = False):
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        
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
        if self.close_file_on_close and not self._file.closed: self._file.close()
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

# ========================================================================
# Read not seekable
# ========================================================================     
class BHXStreamReader(RawIOBase):
    def __init__(self, file: BinaryIO, bhx: BHX, close_file_on_close: bool = False):
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        
        self._bhx = bhx
        self._bhx.reset_stream()
        
        initial_chunk = self._file.read(16) # Read IV
        self._bhx.start_decrypt_stream(initial_chunk)
        
        self._pos: int = 0
        self._last_chunk: Optional[bytes] = None
        assert not self._bhx.use_bcrypt and not self._bhx.use_hmac, \
            "use_hmac and use_bcrypt is not support yet for files"
    
    def close(self): 
        if self.close_file_on_close and not self._file.closed: self._file.close()
        self._closed = True
    def seekable(self) -> bool: False
    def tell(self) -> int: return self._pos
    def read(self, size: int = -1) -> bytes:
        if self._closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        self._file.seek(16+self._pos - self._pos%32) # 16 for READ_IV
        encrypted_data = self._file.read(size + self._pos%32 if size != -1 else -1)
        decrypted_data = bytearray()
        if self._pos%32 != 0:
            self._bhx.counter = (self._pos - self._pos%32) // 32        
        else:
            self._bhx.counter = self._pos // 32    
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

# ========================================================================
# Seekable Read
# ========================================================================     
class BHXBytesIOReaderMemview:
    # no need to implemention as it just use it to get the files size 
    def __init__(self, size: int): 
        self._size = size
    @property
    def nbytes(self) -> int: return self._size     
class BHXBytesIOReader(BytesIO):
    def __init__(self,  file: BinaryIO, bhx: BHX, close_file_on_close: bool = False):
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        
        self._bhx = bhx
        self._bhx.reset_stream()
        
        initial_chunk = self._file.read(16) # Read IV
        self._bhx.start_decrypt_stream(initial_chunk)
        
        self._file.seek(0, SEEK_END)
        self._size = self._file.tell() - 16  # Subtract IV
        self._file.seek(16)
        
        self._pos: int = 0
        self._last_chunk: Optional[bytes] = None
        
        assert not self._bhx.use_bcrypt and not self._bhx.use_hmac, \
            "use_hmac and use_bcrypt is not support yet for files"
        assert not self._bhx.use_new_key_depends_on_old_key, \
            "This implementation requires use_new_key_depends_on_old_key=False"  
    @property
    def closed(self) -> bool: return self._closed
    def close(self): 
        if self.close_file_on_close and not self._file.closed: self._file.close()
        self._closed = True
    def seekable(self) -> bool: return True
    def tell(self) -> int: return self._pos
    def seek(self, pos, whence = 0):
        if whence == SEEK_SET:
            self._pos = pos
        elif whence == SEEK_CUR:
            self._pos += pos
        elif whence == SEEK_END:
            self._pos = self._size + pos
    def read(self, size = -1) -> bytes:
        if self._closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        self._file.seek(16+self._pos - self._pos%32) # 16 for READ_IV
        encrypted_data = self._file.read(size + self._pos%32 if size != -1 else -1)
        decrypted_data = bytearray()
        if self._pos%32 != 0:
            self._bhx.counter = (self._pos - self._pos%32) // 32        
        else:
            self._bhx.counter = self._pos // 32    
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
    def getbuffer(self) -> BHXBytesIOReaderMemview:
        return BHXBytesIOReaderMemview(size = self._size)

# ========================================================================
# Seekable Write
# ======================================================================== 
class BHXBytesIOWriter(BytesIO):
    def __init__(self,  file: BinaryIO, bhx: BHX, close_file_on_close: bool = False):
        raise NotImplementedError("It is not implemented yet...")
        # raise NotADirectoryError("Working...")
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        
        self._bhx = bhx
        self._bhx.reset_stream()
        
        initial_chunk = self._bhx.start_encrypt_stream()
        self._file.write(initial_chunk) # Write IV
        
        self._size = 0  # Subtract IV
        
        self._pos: int = 0
        self._last_chunk: Optional[bytes] = None
        
        assert not self._bhx.use_bcrypt and not self._bhx.use_hmac, \
            "use_hmac and use_bcrypt is not support yet for files"
        assert not self._bhx.use_new_key_depends_on_old_key, \
            "This implementation requires use_new_key_depends_on_old_key=False"  
    @property
    def closed(self) -> bool: return self._closed
    def close(self): 
        if self._last_chunk is not None:
            encrypted_chunk = self._bhx.encrypt_chunk_stream(self._last_chunk)
            self._file.write(encrypted_chunk)
        if self.close_file_on_close and not self._file.closed: self._file.close()
        self._closed = True
    def seekable(self) -> bool: return True
    def tell(self) -> int: return self._pos
    def seek(self, pos, whence = 0):
        # TODO: check if pos is changed more than 32 or one block...
        # TODO: self._last_chunk is not None
        if whence == SEEK_SET:
            self._pos = pos
        elif whence == SEEK_CUR:
            self._pos += pos
        elif whence == SEEK_END:
            self._pos = self._size + pos
            
    def write(self, data: bytes) -> int:
        if self._closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        self._pos += len(data)
        if self._last_chunk is None and len(data) < 32:
            self._last_chunk = data
            return
        if self._last_chunk is not None and len(self._last_chunk + data) < 32:
            self._last_chunk = self._last_chunk + data
            return 
        if self._last_chunk is not None:
            data = self._last_chunk + data
        
        # assert len(data) >= 32       
        self._file.seek(16+self._pos - self._pos%32) # 16 for IV
        if self._pos%32 != 0:
            self._bhx.counter = (self._pos - self._pos%32) // 32        
        else:
            self._bhx.counter = self._pos // 32    
        self._bhx.current_newkey = self._bhx.new_key(self._bhx.key, self._bhx.key, self._bhx.IV, self._bhx.IV, self._bhx.counter)
            
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


@contextmanager
def open_bhx_file(file_name: str, mode: Literal['rb', 'wb'], bhx: BHX) -> Generator[BinaryIO, Any, None]:
    bhx.reset_stream()
    if 'wb' in mode:
        with BHXStreamWriter(open(file_name, mode), bhx, close_file_on_close=True) as writer:
            yield writer
    elif 'rb' in mode:
        with BHXBytesIOReader(open(file_name, mode), bhx, close_file_on_close=True) as writer:
            yield writer
    else:
        raise ValueError("Mode must be 'rb' or 'wb'")