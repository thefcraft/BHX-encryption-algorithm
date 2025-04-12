from contextlib import contextmanager
from typing import Literal, BinaryIO, Optional, Generator, Union, Any, Tuple, Iterable
from io import BufferedWriter, BufferedReader, RawIOBase, SEEK_CUR, SEEK_SET, SEEK_END, BytesIO
from .bhx import BHX
from .utils import deprecated
from .constants import BATCH_SIZE
# from itertools import islice

# def batched(iterable, n):
#     it = iter(iterable)
#     while (batch := list(islice(it, n))):
#         yield batch

# ========================================================================
# Seekable Read-Write
# ======================================================================== 

class BHXBytesIOPseudoMemview:
    # no need to implemention as it just use it to get the files size 
    def __init__(self, size: int): 
        self._size = size
    @property
    def nbytes(self) -> int: return self._size     
    
class BHXByteIO(BytesIO):
    def __init__(self,  file: BinaryIO, bhx: BHX, close_file_on_close: bool = False):
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        self._key = bhx.key
        
        self._iv_size = 16 # store with counter.to_bytes(4, 'big')
        # NOTE: alse if self._iv_size is greater then 32 then we have to see how we handle that because key size is 32
        
        if self._size >= 0:
            initial_chunk = self._file.read(self._iv_size) # Read IV
            self._IV = BHX.encrypt_chunk(initial_chunk, self._key)
        else:
            self._IV = BHX.random_iv(size=self._iv_size)
            initial_chunk = BHX.encrypt_chunk(self._IV, self._key)
            self._file.write(initial_chunk) # Write IV
            
        self._base = self._key+self._key+self._IV+self._IV
        
        self._increase_size_by: int = 0
        
        assert not bhx.use_bcrypt and not bhx.use_hmac, \
            "use_hmac and use_bcrypt is not support yet for files"
        assert not bhx.use_new_key_depends_on_old_key, \
            "This implementation requires use_new_key_depends_on_old_key=False"  
    @property
    def closed(self) -> bool: return self._closed
    def close(self): 
        if self.close_file_on_close and not self._file.closed: self._file.close()
        self._closed = True
    def seekable(self) -> bool: return True
    def readable(self) -> bool: return True
    def writable(self) -> bool: return True
    def tell(self) -> int: return self._file.tell() - self._iv_size
    @property
    def _size(self) -> int:
        raw_pos = self._file.tell()
        self._file.seek(0, SEEK_END)
        size = self.tell()
        self._file.seek(raw_pos, SEEK_SET)
        return size
    def seek(self, offset, whence = 0):
        self._increase_size_by = 0
        if whence == SEEK_SET:
            size = self._size
            assert offset >= 0, "offset can't be -ve"
            if offset <= size:
                self._file.seek(self._iv_size+offset, SEEK_SET)
                return
            new_pos = offset
        elif whence == SEEK_CUR:
            size = self._size
            new_pos = self.tell() + offset
            assert new_pos >= 0, "value after applying offset can't be -ve"
            if new_pos <= size:
                self._file.seek(offset, SEEK_CUR)
                return 
        elif whence == SEEK_END:
            size = self._size
            assert size >= -offset, "value after applying offset can't be -ve"
            if offset<=0:
                self._file.seek(offset, SEEK_END)
                return
            new_pos = size + offset
        
        self._increase_size_by = new_pos - size
        # self._file.seek(0, SEEK_END)
        # data = b'\x00' * (new_pos - size)
        # self.write(data)
    def truncate(self, size: Optional[int] = None) -> int: 
        if size == None: return self._file.truncate() - self._iv_size
        else: return self._file.truncate(size + self._iv_size) - self._iv_size
    def write(self, data: bytes) -> int:
        if self.closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        return_value = len(data)
        if self._increase_size_by != 0:
            self._file.seek(0, SEEK_END)
            data_zeros = b'\x00' * self._increase_size_by
            self._increase_size_by = 0
            self.write(data_zeros)
        
        pos = self.tell()
        counter = (pos - pos%32) // 32
        self._file.seek(self._iv_size+pos - pos%32) # 16 for READ_IV
        
        if pos%32 != 0:
            old_data = self._file.read(32)
            if len(old_data) != 0:
                self._file.seek(-len(old_data), SEEK_CUR)
                current_newkey = BHX.new_key(self._key, self._key, self._IV, self._IV, counter)
                decrypted_old_data = BHX.encrypt_chunk(old_data, current_newkey)
                data = decrypted_old_data[:pos%32] + data

        indices = range(0, len(data)-32, 32)
        total_chunks = len(indices)
        for batch_start in range(0, total_chunks, BATCH_SIZE):
            len_current_chunk = min(BATCH_SIZE, total_chunks - batch_start)
            chunks_start_idx = indices[batch_start]
            next_chunk_start_idx = chunks_start_idx + len_current_chunk*32
            chunk_idx = batch_start // BATCH_SIZE
            
            curr_counter_start = counter+(chunk_idx*BATCH_SIZE)
            # current_newkey = bytearray(b''.join(
            #     BHX.new_key(self._key, self._key, self._IV, self._IV, curr_counter) 
            #     for curr_counter in range(curr_counter_start, curr_counter_start+len_current_chunk)
            # ))
            # chunk = data[chunks_start_idx:next_chunk_start_idx]
            # encrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
            encrypted_chunk = BHX.encrypt_chunk_longer_little_unsafe(
                base=self._base,
                counter_start=curr_counter_start,
                counter_end=curr_counter_start+len_current_chunk,
                chunk=data[chunks_start_idx:next_chunk_start_idx]
            )
            self._file.write(encrypted_chunk)
            
        # for chunk_idx, chunks in enumerate(batched(range(0, len(data)-32, 32), 1000)):
        #     curr_counter_start = counter+(chunk_idx*1000)
        #     current_newkey = bytearray(b''.join(
        #         BHX.new_key(self._key, self._key, self._IV, self._IV, curr_counter) 
        #         for curr_counter in range(curr_counter_start, curr_counter_start+len(chunks))
        #     ))
        #     chunk = bytearray(b''.join(data[i:i+32] for i in chunks))
        #     encrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
        #     self._file.write(encrypted_chunk)
            
        # for curr_counter, i in enumerate(range(0, len(data)-32, 32), counter):
        #     chunk = data[i:i+32] 
        #     current_newkey = BHX.new_key(self._key, self._key, self._IV, self._IV, curr_counter)
        #     encrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
        #     self._file.write(encrypted_chunk)
            
        if (iterations := (len(data) - 1) // 32) > 0: # max(0, (end - start + step - 1) // step)
            counter += iterations 
        last_i = ((len(data)-32 - 1) // 32) * 32 # (n-1 // step) * step
        
        chunk = data[last_i+32:]
        current_newkey = BHX.new_key(self._key, self._key, self._IV, self._IV, counter)
        if len(data)%32 != 0:
            old_data = self._file.read(32)
            if len(old_data) != 0:
                self._file.seek(-len(old_data), SEEK_CUR)
                decrypted_old_data = BHX.encrypt_chunk(old_data, current_newkey)
                chunk = chunk + decrypted_old_data[len(chunk):32]
        encrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
        self._file.write(encrypted_chunk)
        return return_value
        
    def read(self, size = -1) -> bytes:
        if self.closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        pos = self.tell()
        self._file.seek(self._iv_size+pos - pos%32) # 16 for READ_IV
        encrypted_data = self._file.read(size + pos%32 if size != -1 else -1)
        decrypted_data = bytearray()
        counter = (pos - pos%32) // 32
        current_newkey = BHX.new_key(self._key, self._key, self._IV, self._IV, counter)
            
        if len(encrypted_data) != 0:
            chunk = encrypted_data[:32]
            decrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
            decrypted_data.extend(decrypted_chunk[pos%32:])
            counter+=1
            
        indices = range(32, len(encrypted_data), 32)
        total_chunks = len(indices)
        for batch_start in range(0, total_chunks, BATCH_SIZE):
            len_current_chunk = min(BATCH_SIZE, total_chunks - batch_start)
            chunks_start_idx = indices[batch_start]
            next_chunk_start_idx = chunks_start_idx + len_current_chunk*32
            chunk_idx = batch_start // BATCH_SIZE
            
            curr_counter_start = counter+(chunk_idx*BATCH_SIZE)
            # current_newkey = bytearray(b''.join(
            #     BHX.new_key(self._key, self._key, self._IV, self._IV, curr_counter) 
            #     for curr_counter in range(curr_counter_start, curr_counter_start+len_current_chunk)
            # ))
            # chunk = encrypted_data[chunks_start_idx:next_chunk_start_idx]
            # decrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
            decrypted_chunk = BHX.encrypt_chunk_longer_little_unsafe(
                base=self._base,
                counter_start=curr_counter_start,
                counter_end=curr_counter_start+len_current_chunk,
                chunk=encrypted_data[chunks_start_idx:next_chunk_start_idx]
            )
            decrypted_data.extend(decrypted_chunk)
        
        # for chunk_idx, chunks in enumerate(batched(range(32, len(encrypted_data), 32), 1000)):
        #     curr_counter_start = counter+(chunk_idx*1000)
        #     current_newkey = bytearray(b''.join(
        #         BHX.new_key(self._key, self._key, self._IV, self._IV, curr_counter) 
        #         for curr_counter in range(curr_counter_start, curr_counter_start+len(chunks))
        #     ))
        #     chunk = bytearray(b''.join(encrypted_data[i:i+32] for i in chunks))
        #     decrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
        #     decrypted_data.extend(decrypted_chunk)
            
        # for counter, i in enumerate(range(32, len(encrypted_data), 32), counter):
        #     current_newkey = BHX.new_key(self._key, self._key, self._IV, self._IV, counter)
        #     chunk = encrypted_data[i:i+32]
        #     decrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
        #     decrypted_data.extend(decrypted_chunk)
            
        return bytes(decrypted_data)
    def getbuffer(self) -> BHXBytesIOPseudoMemview:
        # just have .nbytes property
        return BHXBytesIOPseudoMemview(size = self._size)
    
    def writelines(self, lines):
        for line in lines:
            self.write(line)
    
@contextmanager
def open_bhx_file(file_name: str, mode: Literal['w+b', 'r+b'], bhx: BHX) -> Generator[BHXByteIO, Any, None]:
    bhx.reset_stream()
    with BHXByteIO(open(file_name, mode), bhx, close_file_on_close=True) as writer:
        yield writer

    









# ========================================================================

#  --------------------------deprecated-----------------------------------

# ========================================================================









# ========================================================================
# Write not seekable
# ========================================================================
@deprecated(reason="Please see BHXBytesIO which is faster")
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
        # assert self._bhx.use_new_key_depends_on_old_key, \
        #     "This implementation requires use_new_key_depends_on_old_key=True"  
    
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
# 
# ========================================================================
# Read not seekable
# ========================================================================     
@deprecated(reason="Please see BHXBytesIO which is faster")
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
        # assert self._bhx.use_new_key_depends_on_old_key, \
        #     "This implementation requires use_new_key_depends_on_old_key=True"  
    
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
@deprecated(reason="Please use BHXBytesIO insted")
class BHXBytesIOReader(BytesIO):
    def __init__(self,  file: BinaryIO, bhx: BHX, 
                 close_file_on_close: bool = False):
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        
        self._bhx = bhx
        
        initial_chunk = self._file.read(16) # Read IV
        self._IV = BHX.encrypt_chunk(initial_chunk, self._bhx.key)
        
        self._file.seek(0, SEEK_END)
        self._size = self._file.tell() - 16  # Subtract IV
        self._file.seek(16)
        
        self._pos: int = 0
        
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
    def readable(self) -> bool: return True
    def writable(self) -> bool: return False
    def write(self, data: bytes): raise OSError("File is not writable")
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
        counter = (self._pos - self._pos%32) // 32
        current_newkey = BHX.new_key(self._bhx.key, self._bhx.key, self._IV, self._IV, counter)
            
        if len(encrypted_data) != 0:
            chunk = encrypted_data[:32]
            decrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
            decrypted_data.extend(decrypted_chunk[self._pos%32:])
            counter+=1
        for i in range(32, len(encrypted_data), 32):
            current_newkey = BHX.new_key(self._bhx.key, self._bhx.key, self._IV, self._IV, counter)
            chunk = encrypted_data[i:i+32]
            decrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
            decrypted_data.extend(decrypted_chunk)
            counter+=1
        self._pos += len(decrypted_data)
        return bytes(decrypted_data)
    def getbuffer(self) -> BHXBytesIOPseudoMemview:
        return BHXBytesIOPseudoMemview(size = self._size)

# ========================================================================
# Seekable Write
# ======================================================================== 
@deprecated(reason="Please use BHXBytesIO insted")
class BHXBytesIOWriter(BytesIO):
    def __init__(self,  file: BinaryIO, bhx: BHX, close_file_on_close: bool = False):
        self._file = file
        self._closed = False
        self.close_file_on_close = close_file_on_close
        
        self._bhx = bhx
        
        self._IV = BHX.random_iv()
        initial_chunk = BHX.encrypt_chunk(self._IV, self._bhx.key)
        self._file.write(initial_chunk) # Write IV
        
        self._increase_size_by: int = 0
        
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
    def tell(self) -> int: return self._file.tell() - 16
    @property
    def _size(self) -> int:
        raw_pos = self._file.tell()
        self._file.seek(0, SEEK_END)
        size = self.tell()
        self._file.seek(raw_pos, SEEK_SET)
        return size
    def seek(self, offset, whence = 0):
        self._increase_size_by = 0
        if whence == SEEK_SET:
            size = self._size
            assert offset >= 0, "offset can't be -ve"
            if offset <= size:
                self._file.seek(16+offset, SEEK_SET)
                return
            new_pos = offset
        elif whence == SEEK_CUR:
            size = self._size
            new_pos = self.tell() + offset
            assert new_pos >= 0, "value after applying offset can't be -ve"
            if new_pos <= size:
                self._file.seek(offset, SEEK_CUR)
                return 
        elif whence == SEEK_END:
            size = self._size
            assert size >= -offset, "value after applying offset can't be -ve"
            if offset<=0:
                self._file.seek(offset, SEEK_END)
                return
            new_pos = size + offset
        
        self._increase_size_by = new_pos - size
        # self._file.seek(0, SEEK_END)
        # data = b'\x00' * (new_pos - size)
        # self.write(data)
        
    def truncate(self, size: Optional[int] = None) -> int: 
        if size == None: return self._file.truncate() - 16
        else: return self._file.truncate(size + 16) - 16
    def write(self, data: bytes) -> int:
        if self._closed or self._file.closed:
            raise ValueError("I/O operation on closed file")
        
        if self._increase_size_by != 0:
            self._file.seek(0, SEEK_END)
            data_zeros = b'\x00' * self._increase_size_by
            self._increase_size_by = 0
            self.write(data_zeros)
        
        pos = self.tell()
        counter = (pos - pos%32) // 32
        self._file.seek(16+pos - pos%32) # 16 for READ_IV
        
        if pos%32 != 0:
            old_data = self._file.read(32)
            if len(old_data) != 0:
                self._file.seek(-len(old_data), SEEK_CUR)
                current_newkey = BHX.new_key(self._bhx.key, self._bhx.key, self._IV, self._IV, counter)
                decrypted_old_data = BHX.encrypt_chunk(old_data, current_newkey)
                data = decrypted_old_data[:pos%32] + data
        
        for i in range(0, len(data)-32, 32):
            chunk = data[i:i+32]
            current_newkey = BHX.new_key(self._bhx.key, self._bhx.key, self._IV, self._IV, counter)
            encrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
            self._file.write(encrypted_chunk)
            counter+=1
        
        last_i = ((len(data)-32 - 1) // 32) * 32 # (n-1 // step) * step
        
        chunk = data[last_i+32:]
        current_newkey = BHX.new_key(self._bhx.key, self._bhx.key, self._IV, self._IV, counter)
        if len(data)%32 != 0:
            old_data = self._file.read(32)
            if len(old_data) != 0:
                self._file.seek(-len(old_data), SEEK_CUR)
                decrypted_old_data = BHX.encrypt_chunk(old_data, current_newkey)
                chunk = chunk + decrypted_old_data[len(chunk):32]
        encrypted_chunk = BHX.encrypt_chunk(chunk, current_newkey)
        self._file.write(encrypted_chunk)

