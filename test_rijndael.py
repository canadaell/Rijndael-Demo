import ctypes
import os
import random
import pytest

# Load the shared library
rijndael_lib = ctypes.CDLL('./rijndael.so')

# Define function prototypes
rijndael_lib.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael_lib.sub_bytes.restype = None

rijndael_lib.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael_lib.shift_rows.restype = None

rijndael_lib.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael_lib.mix_columns.restype = None

rijndael_lib.add_round_key.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
rijndael_lib.add_round_key.restype = None

rijndael_lib.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael_lib.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

rijndael_lib.aes_encrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
]
rijndael_lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

rijndael_lib.aes_decrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
]
rijndael_lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

# Helper functions
def to_byte_array(data):
    return (ctypes.c_ubyte * len(data))(*data)

def from_byte_array(ptr, length=16):
    if ptr:
        return [ptr[i] for i in range(length)]
    return None

# Python reference implementation
class Rijndael:
    # S-box from rijndael.c
    sbox = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]

    @staticmethod
    def sub_bytes(block):
        # Ensure all values are within 0-255 range
        return [Rijndael.sbox[b & 0xff] for b in block]

    @staticmethod
    def shift_rows(block):
        """
        Shift rows operation matching C implementation.
        Block is treated as 4x4 matrix in row-major order:
        [0,1,2,3]
        [4,5,6,7]
        [8,9,10,11]
        [12,13,14,15]
        """
        new_block = block.copy()
        
        # Row 0: no shift
        
        # Row 1: shift left by 1 (rotate left)
        new_block[4] = block[5]
        new_block[5] = block[6]
        new_block[6] = block[7]
        new_block[7] = block[4]
        
        # Row 2: shift left by 2 (swap positions)
        new_block[8] = block[10]
        new_block[9] = block[11]
        new_block[10] = block[8]
        new_block[11] = block[9]
        
        # Row 3: shift left by 3 (equivalent to right by 1)
        new_block[12] = block[15]
        new_block[13] = block[12]
        new_block[14] = block[13]
        new_block[15] = block[14]
        
        return new_block

    @staticmethod 
    def gmul(a, b):
        p = 0
        a = a & 0xff  # Ensure byte range
        b = b & 0xff
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xff  # Keep in byte range
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p & 0xff  # Ensure byte range

    @staticmethod
    def mix_columns(block):
        tmp = [0]*16
        for i in range(4):
            tmp[i*4]   = Rijndael.gmul(0x02, block[i*4]) ^ Rijndael.gmul(0x03, block[i*4+1]) ^ block[i*4+2] ^ block[i*4+3]
            tmp[i*4+1] = block[i*4] ^ Rijndael.gmul(0x02, block[i*4+1]) ^ Rijndael.gmul(0x03, block[i*4+2]) ^ block[i*4+3]
            tmp[i*4+2] = block[i*4] ^ block[i*4+1] ^ Rijndael.gmul(0x02, block[i*4+2]) ^ Rijndael.gmul(0x03, block[i*4+3])
            tmp[i*4+3] = Rijndael.gmul(0x03, block[i*4]) ^ block[i*4+1] ^ block[i*4+2] ^ Rijndael.gmul(0x02, block[i*4+3])
        return tmp

    @staticmethod
    def encrypt_block(plaintext, key):
        state = plaintext.copy()
        round_keys = Rijndael.expand_key(key)
        
        # Initial round
        state = [state[i] ^ round_keys[i] for i in range(16)]
        
        # 9 main rounds
        for round in range(1, 10):
            state = Rijndael.sub_bytes(state)
            state = Rijndael.shift_rows(state)
            state = Rijndael.mix_columns(state)
            state = [state[i] ^ round_keys[round*16 + i] for i in range(16)]
        
        # Final round
        state = Rijndael.sub_bytes(state)
        state = Rijndael.shift_rows(state)
        state = [state[i] ^ round_keys[10*16 + i] for i in range(16)]
        
        return state
    
    @staticmethod
    def decrypt_block(ciphertext, key):
        state = ciphertext.copy()
        round_keys = Rijndael.expand_key(key)
        
        # Initial round
        state = [state[i] ^ round_keys[10*16 + i] for i in range(16)]
        
        # 9 main rounds
        for round in range(9, 0, -1):
            state = Rijndael.invert_shift_rows(state)
            state = Rijndael.invert_sub_bytes(state)
            state = [state[i] ^ round_keys[round*16 + i] for i in range(16)]
            state = Rijndael.invert_mix_columns(state)
        
        # Final round
        state = Rijndael.invert_shift_rows(state)
        state = Rijndael.invert_sub_bytes(state)
        state = [state[i] ^ round_keys[i] for i in range(16)]
        
        return state

    @staticmethod
    def invert_sub_bytes(block):
        # Inverse S-box from rijndael.c
        inv_sbox = [
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        ]
        return [inv_sbox[b] for b in block]

    @staticmethod
    def invert_shift_rows(block):
        """
        Inverse shift rows operation matching C implementation.
        Block is treated as 4x4 matrix in row-major order:
        [0,1,2,3]
        [4,5,6,7]
        [8,9,10,11]
        [12,13,14,15]
        """
        new_block = block.copy()
        
        # Row 0: no shift
        
        # Row 1: shift right by 1 (rotate right)
        new_block[4] = block[7]
        new_block[5] = block[4]
        new_block[6] = block[5]
        new_block[7] = block[6]
        
        # Row 2: shift right by 2 (swap positions)
        new_block[8] = block[10]
        new_block[9] = block[11]
        new_block[10] = block[8]
        new_block[11] = block[9]
        
        # Row 3: shift right by 3 (equivalent to left by 1)
        new_block[12] = block[13]
        new_block[13] = block[14]
        new_block[14] = block[15]
        new_block[15] = block[12]
        
        return new_block

    @staticmethod
    def invert_mix_columns(block):
        tmp = [0]*16
        for i in range(4):
            tmp[i*4]   = Rijndael.gmul(0x0e, block[i*4]) ^ Rijndael.gmul(0x0b, block[i*4+1]) ^ Rijndael.gmul(0x0d, block[i*4+2]) ^ Rijndael.gmul(0x09, block[i*4+3])
            tmp[i*4+1] = Rijndael.gmul(0x09, block[i*4]) ^ Rijndael.gmul(0x0e, block[i*4+1]) ^ Rijndael.gmul(0x0b, block[i*4+2]) ^ Rijndael.gmul(0x0d, block[i*4+3])
            tmp[i*4+2] = Rijndael.gmul(0x0d, block[i*4]) ^ Rijndael.gmul(0x09, block[i*4+1]) ^ Rijndael.gmul(0x0e, block[i*4+2]) ^ Rijndael.gmul(0x0b, block[i*4+3])
            tmp[i*4+3] = Rijndael.gmul(0x0b, block[i*4]) ^ Rijndael.gmul(0x0d, block[i*4+1]) ^ Rijndael.gmul(0x09, block[i*4+2]) ^ Rijndael.gmul(0x0e, block[i*4+3])
        return tmp

    @staticmethod
    def expand_key(key):
        # Rcon table
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        
        # Initialize expanded key with original key
        expanded_key = key.copy()
        
        for i in range(4, 44):
            temp = expanded_key[(i-1)*4:i*4]
            
            if i % 4 == 0:
                # Rotate word
                temp = [temp[1], temp[2], temp[3], temp[0]]
                # SubBytes
                temp = [Rijndael.sbox[b] for b in temp]
                # XOR with Rcon
                temp[0] ^= rcon[i//4 - 1]
            
            # XOR with word from 4 positions back
            expanded_key += [
                expanded_key[(i-4)*4 + j] ^ temp[j]
                for j in range(4)
            ]
        
        return expanded_key

# Unit tests
def test_sub_bytes():
    for _ in range(3):
        # Generate random input
        input_data = [random.randint(0, 255) for _ in range(16)]
        c_input = to_byte_array(input_data.copy())
        
        # Call C implementation (modifies in-place)
        rijndael_lib.sub_bytes(c_input)
        c_output = from_byte_array(c_input)
        
        # Call Python implementation
        py_output = Rijndael.sub_bytes(input_data.copy())
        
        assert c_output == py_output

def test_shift_rows():
    for _ in range(3):
        input_data = [random.randint(0, 255) for _ in range(16)]
        c_input = to_byte_array(input_data.copy())
        
        # Call C implementation (modifies in-place)
        rijndael_lib.shift_rows(c_input)
        c_output = from_byte_array(c_input)
        
        py_output = Rijndael.shift_rows(input_data.copy())
        
        assert c_output == py_output

def test_mix_columns():
    for _ in range(3):
        input_data = [random.randint(0, 255) for _ in range(16)]
        c_input = to_byte_array(input_data.copy())
        
        # Call C implementation (modifies in-place)
        rijndael_lib.mix_columns(c_input)
        c_output = from_byte_array(c_input)
        
        py_output = Rijndael.mix_columns(input_data.copy())
        
        assert c_output == py_output

def test_add_round_key():
    for _ in range(3):
        block = [random.randint(0, 255) for _ in range(16)]
        round_key = [random.randint(0, 255) for _ in range(16)]
        c_block = to_byte_array(block.copy())
        c_key = to_byte_array(round_key)
        
        # Call C implementation (modifies in-place)
        rijndael_lib.add_round_key(c_block, c_key)
        c_output = from_byte_array(c_block)
        
        # Python implementation is simple XOR
        py_output = [block[i] ^ round_key[i] for i in range(16)]
        
        assert c_output == py_output

def test_invert_sub_bytes():
    for _ in range(3):
        # Generate random input
        input_data = [random.randint(0, 255) for _ in range(16)]
        c_input = to_byte_array(input_data.copy())
        
        # First apply sub_bytes then invert to verify roundtrip
        rijndael_lib.sub_bytes(c_input)
        rijndael_lib.invert_sub_bytes(c_input)
        c_output = from_byte_array(c_input)
        
        assert c_output == input_data

def test_invert_shift_rows():
    for _ in range(3):
        input_data = [random.randint(0, 255) for _ in range(16)]
        c_input = to_byte_array(input_data.copy())
        
        # First shift then invert to verify roundtrip
        rijndael_lib.shift_rows(c_input)
        rijndael_lib.invert_shift_rows(c_input)
        c_output = from_byte_array(c_input)
        
        assert c_output == input_data

def test_invert_mix_columns():
    for _ in range(3):
        input_data = [random.randint(0, 255) for _ in range(16)]
        c_input = to_byte_array(input_data.copy())
        
        # First mix then invert to verify roundtrip
        rijndael_lib.mix_columns(c_input)
        rijndael_lib.invert_mix_columns(c_input)
        c_output = from_byte_array(c_input)
        
        assert c_output == input_data

def test_key_expansion():
    for _ in range(3):
        key = [random.randint(0, 255) for _ in range(16)]
        
        c_key = to_byte_array(key)
        c_result = rijndael_lib.expand_key(c_key)
        c_output = from_byte_array(c_result, 176)  # 11 round keys
        
        # Verify first round key matches original key
        assert c_output[:16] == key
        
        # Verify subsequent round keys are different
        for i in range(1, 11):
            assert c_output[i*16:(i+1)*16] != key

# End-to-end tests
def test_encrypt_decrypt_roundtrip():
    for _ in range(3):
        plaintext = os.urandom(16)
        key = os.urandom(16)
        
        # Encrypt with C
        c_plain = to_byte_array(plaintext)
        c_key = to_byte_array(key)
        c_cipher = rijndael_lib.aes_encrypt_block(c_plain, c_key)
        ciphertext = from_byte_array(c_cipher)
        
        # Decrypt with C
        c_cipher = to_byte_array(ciphertext)
        c_decrypted = rijndael_lib.aes_decrypt_block(c_cipher, c_key)
        decrypted = from_byte_array(c_decrypted)
        
        assert decrypted == list(plaintext)

def test_python_vs_c_implementation():
    for _ in range(3):
        plaintext = os.urandom(16)
        key = os.urandom(16)
        
        # Encrypt with C
        c_plain = to_byte_array(plaintext)
        c_key = to_byte_array(key)
        c_cipher = rijndael_lib.aes_encrypt_block(c_plain, c_key)
        c_ciphertext = from_byte_array(c_cipher)
        
        # Encrypt with Python
        py_ciphertext = Rijndael.encrypt_block(list(plaintext), list(key))
        
        # Compare ciphertexts
        assert c_ciphertext == py_ciphertext
        
        # Decrypt with Python
        py_decrypted = Rijndael.decrypt_block(py_ciphertext, list(key))
        
        # Verify roundtrip
        assert py_decrypted == list(plaintext)

def test_boundary_cases():
    # Test all zeros
    zero_plain = [0]*16
    zero_key = [0]*16
    zero_cipher = Rijndael.encrypt_block(zero_plain, zero_key)
    zero_decrypted = Rijndael.decrypt_block(zero_cipher, zero_key)
    assert zero_decrypted == zero_plain
    
    # Test all ones
    ones_plain = [0xff]*16
    ones_key = [0xff]*16
    ones_cipher = Rijndael.encrypt_block(ones_plain, ones_key)
    ones_decrypted = Rijndael.decrypt_block(ones_cipher, ones_key)
    assert ones_decrypted == ones_plain
    
    # Test alternating pattern
    alt_plain = [0x55, 0xaa]*8
    alt_key = [0xaa, 0x55]*8
    alt_cipher = Rijndael.encrypt_block(alt_plain, alt_key)
    alt_decrypted = Rijndael.decrypt_block(alt_cipher, alt_key)
    assert alt_decrypted == alt_plain

if __name__ == '__main__':
    pytest.main()
