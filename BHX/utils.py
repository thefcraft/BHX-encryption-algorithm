import string
from typing import Union
from .bhx import BHX
from hashlib import sha256
import os

import warnings
import functools


class Base256toN:
    def __init__(self, valid_char: str = (
        string.ascii_lowercase + 
        string.ascii_uppercase + 
        string.digits + 
        "-._~!"
    )):
        # Remove duplicates and sort to get a consistent mapping.
        self.valid_char = ''.join(sorted(set(valid_char)))
        n = len(self.valid_char)
        # We need at least one symbol and strictly less than 256 symbols.
        assert 0 < n < 256, "n must be between 1 and 255 including both bounds"
        self.BASE = n  # New destination base
        
        # Pre-calculate the "order" (to go from digit value to character code) and
        # a fast mapping (from character to digit value).
        self.order = [ord(c) for c in self.valid_char]
        self.char = {c: i for i, c in enumerate(self.valid_char)}

    def encode(self, data: bytes) -> bytes:
        """Converts a bytes object (base 256) into the new base represented as bytes."""
        # Count leading zeros so that we can preserve them.
        n_leading_zeros = 0
        for b in data:
            if b == 0:
                n_leading_zeros += 1
            else:
                break

        # Instead of doing a digit‑by‑digit division in Python,
        # we convert the entire bytes object into a huge integer.
        num = int.from_bytes(data, byteorder="big")
        if num == 0:
            # If the number is zero, just return one "zero" digit.
            converted = bytes([self.order[0]])
        else:
            digits = []
            # Divide the large integer by BASE repeatedly.
            while num:
                num, rem = divmod(num, self.BASE)
                # Append the corresponding symbol (stored as its ord value).
                digits.append(self.order[rem])
            digits.reverse()
            converted = bytes(digits)

        # Prepend any leading "zero" digits (each represented by self.order[0])
        return bytes([self.order[0]]) * n_leading_zeros + converted

    def decode(self, data: bytes) -> bytes:
        """Converts a bytes object from the custom base (as created by encrypt) back to base 256."""
        # Count leading "zero" digits, which correspond to zeros.
        n_leading = 0
        zero_char_code = self.order[0]
        for b in data:
            if b == zero_char_code:
                n_leading += 1
            else:
                break

        # Reconstruct the integer from the given base digits.
        num = 0
        # Convert each character in data to its corresponding digit value using the dict.
        for b in data:
            # Since b is the ordinal value of a character in our valid_char set,
            # convert it to a character and look it up:
            num = num * self.BASE + self.char.get(chr(b), 0)

        if num == 0:
            converted = b"\x00"
        else:
            # Calculate how many bytes are needed.
            byte_length = (num.bit_length() + 7) // 8
            converted = num.to_bytes(byte_length, byteorder="big")

        # Restore any leading zero bytes.
        return b"\x00" * n_leading + converted

_default_Base256toN = Base256toN()
def safe_encode(data: bytes) -> str:
    return _default_Base256toN.encode(data).decode()
def safe_decode(data: str) -> bytes:
    return _default_Base256toN.decode(data.encode())

def encode_filename(bhx: BHX, filename: Union[str, bytes]) -> str:
    if isinstance(filename, str): filename = filename.encode()
    name = bhx.encrypt(filename, use_iv=sha256(bhx.key).digest())
    return f"{safe_encode(name)}.enc"

def decode_filename(bhx: BHX, filename: Union[str, bytes]) -> str:
    if not isinstance(filename, str): filename = filename.decode()
    name = safe_decode(filename.removesuffix(".enc"))
    return bhx.decrypt(name).decode()


def deprecated(reason="This function is deprecated"):
    def decorator(obj):
        # If it's a class
        if isinstance(obj, type):
            orig_init = obj.__init__

            @functools.wraps(orig_init)
            def new_init(self, *args, **kwargs):
                warnings.warn(
                    f"{obj.__name__} is deprecated: {reason}",
                    DeprecationWarning,
                    stacklevel=2
                )
                return orig_init(self, *args, **kwargs)

            obj.__init__ = new_init
            return obj

        # If it's a function or method
        elif callable(obj):
            @functools.wraps(obj)
            def wrapper(*args, **kwargs):
                warnings.warn(
                    f"{obj.__name__} is deprecated: {reason}",
                    DeprecationWarning,
                    stacklevel=2
                )
                return obj(*args, **kwargs)

            return wrapper

        else:
            raise TypeError("Unsupported type for @deprecated")
    return decorator
