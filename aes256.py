import os
import hmac
import hashlib
import math
import json
import base64
import secrets
from typing import List, Tuple, Union, BinaryIO, Dict, Callable
from pathlib import Path
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw
from argon2.low_level import Type
import time
import psutil
# Add cryptography library for standard AES-GCM implementation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AES256:
    """
    Implementation of the Advanced Encryption Standard (AES-256) algorithm
    with HMAC-SHA256 authentication and integrity checking.
    """
    def __init__(self):
        """Initialize AES cipher with pre-computed tables and security parameters."""
        self.sbox, self.inv_sbox = self._generate_sbox()
        self.rcon = self._generate_rcon()
        self.round_keys = None
        self._init_gf_tables()
        self.HMAC_KEY_SIZE = 32

    def _generate_sbox(self):
        """Generate the AES S-box and its inverse using finite field arithmetic."""
        sbox = []
        inv_sbox = [0] * 256
        p = 0x11B
        
        def mul_gf256(a, b):
            result = 0
            while b:
                if b & 1:
                    result ^= a
                a <<= 1
                if a & 0x100:
                    a ^= p
                b >>= 1
            return result & 0xFF
        
        def mod_inverse(a):
            if a == 0:
                return 0
            for x in range(256):
                if mul_gf256(a, x) == 1:
                    return x
            return 0
        
        for i in range(256):
            inverse = mod_inverse(i)
            transformed = inverse
            for _ in range(4):
                transformed ^= (transformed << 1) & 0xFF
                transformed ^= (transformed >> 7) & 0xFF
            transformed ^= 0x63
            sbox.append(transformed)
            inv_sbox[transformed] = i
        
        return sbox, inv_sbox

    def _generate_rcon(self):
        """Generate round constants."""
        rcon = []
        value = 1
        for _ in range(16):
            rcon.append(value)
            value = ((value << 1) ^ 0x1B) if value & 0x80 else (value << 1)
            value &= 0xFF
        return rcon

    def _init_gf_tables(self):
        """Initialize Galois Field multiplication tables."""
        self.gf_mul = [[self._galois_mult(i, j) for j in range(256)] for i in range(16)]

    def _galois_mult(self, a, b):
        """Galois Field multiplication."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p & 0xff

    def expand_key(self, key):
        """Expand the encryption key into round keys."""
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        
        expanded = []
        for i in range(0, 32, 4):
            expanded.append([key[i], key[i+1], key[i+2], key[i+3]])
        
        for i in range(8, 60):
            temp = expanded[i-1][:]
            if i % 8 == 0:
                temp = temp[1:] + temp[:1]
                temp = [self.sbox[b] for b in temp]
                temp[0] ^= self.rcon[i // 8 - 1]
            elif i % 8 == 4:
                temp = [self.sbox[b] for b in temp]
            expanded.append([expanded[i-8][j] ^ temp[j] for j in range(4)])
        
        round_keys = []
        for i in range(0, 60, 4):
            round_key = [[0] * 4 for _ in range(4)]
            for j in range(4):
                for k in range(4):
                    round_key[k][j] = expanded[i + j][k]
            round_keys.append(round_key)
        
        return round_keys

    def _sub_bytes(self, state):
        """Apply SubBytes transformation."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]
        return state

    def _inv_sub_bytes(self, state):
        """Apply inverse SubBytes transformation."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
        return state

    def _shift_rows(self, state):
        """Apply ShiftRows transformation."""
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def _inv_shift_rows(self, state):
        """Apply inverse ShiftRows transformation."""
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def _mix_columns(self, state):
        """Apply MixColumns transformation."""
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            column = self._mix_single_column(column)
            for j in range(4):
                state[j][i] = column[j]
        return state

    def _mix_single_column(self, column):
        """Mix a single column."""
        tmp = column[:]
        column[0] = (self.gf_mul[2][tmp[0]] ^ self.gf_mul[3][tmp[1]] ^ tmp[2] ^ tmp[3])
        column[1] = (tmp[0] ^ self.gf_mul[2][tmp[1]] ^ self.gf_mul[3][tmp[2]] ^ tmp[3])
        column[2] = (tmp[0] ^ tmp[1] ^ self.gf_mul[2][tmp[2]] ^ self.gf_mul[3][tmp[3]])
        column[3] = (self.gf_mul[3][tmp[0]] ^ tmp[1] ^ tmp[2] ^ self.gf_mul[2][tmp[3]])
        return column

    def _inv_mix_columns(self, state):
        """Apply inverse MixColumns transformation."""
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            column = self._inv_mix_single_column(column)
            for j in range(4):
                state[j][i] = column[j]
        return state

    def _inv_mix_single_column(self, column):
        """Mix a single column in inverse operation."""
        tmp = column[:]
        column[0] = (self.gf_mul[14][tmp[0]] ^ self.gf_mul[11][tmp[1]] ^
                    self.gf_mul[13][tmp[2]] ^ self.gf_mul[9][tmp[3]])
        column[1] = (self.gf_mul[9][tmp[0]] ^ self.gf_mul[14][tmp[1]] ^
                    self.gf_mul[11][tmp[2]] ^ self.gf_mul[13][tmp[3]])
        column[2] = (self.gf_mul[13][tmp[0]] ^ self.gf_mul[9][tmp[1]] ^
                    self.gf_mul[14][tmp[2]] ^ self.gf_mul[11][tmp[3]])
        column[3] = (self.gf_mul[11][tmp[0]] ^ self.gf_mul[13][tmp[1]] ^
                    self.gf_mul[9][tmp[2]] ^ self.gf_mul[14][tmp[3]])
        return column

    def _add_round_key(self, state, round_key):
        """Apply AddRoundKey transformation."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    def _generate_hmac_key(self) -> bytes:
        """Generate a random key for HMAC."""
        return os.urandom(self.HMAC_KEY_SIZE)

    def _calculate_hmac(self, data: bytes, hmac_key: bytes) -> bytes:
        """Calculate HMAC-SHA256 of the data."""
        return hmac.new(hmac_key, data, hashlib.sha256).digest()

    def _verify_hmac(self, data: bytes, hmac_key: bytes, expected_hmac: bytes) -> bool:
        """Verify HMAC-SHA256 of the data."""
        calculated_hmac = self._calculate_hmac(data, hmac_key)
        return hmac.compare_digest(calculated_hmac, expected_hmac)

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength."""
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            return False, "Password must contain uppercase, lowercase, numbers, and special characters"
        
        common_patterns = ['123', 'abc', 'qwerty', 'password']
        if any(pattern.lower() in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns"
        
        return True, "Password meets security requirements"

    def generate_secure_password(self, length: int = 32) -> Tuple[bytes, str]:
        """Generate a secure password."""
        password_bytes = secrets.token_bytes(length)
        readable_password = base64.b64encode(password_bytes).decode('utf-8')
        return password_bytes, readable_password

    def save_encryption_data(self, path: Union[str, Path], iv: bytes, hmac_key: bytes,
                           salt: bytes, generated_password: bytes = None) -> Path:
        """Save encryption data to a file."""
        path = Path(path)
        key_file = path.with_suffix('.key')
        
        encryption_data = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'hmac_key': base64.b64encode(hmac_key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
        
        if generated_password is not None:
            encryption_data['generated_password'] = base64.b64encode(generated_password).decode('utf-8')
        
        with open(key_file, 'w') as f:
            json.dump(encryption_data, f, indent=4)
        
        os.chmod(key_file, 0o600)
        return key_file

    def load_encryption_data(self, key_file: Union[str, Path]) -> Tuple[bytes, bytes, bytes, bytes]:
        """Load encryption data from a file."""
        with open(key_file, 'r') as f:
            data = json.load(f)
        
        try:
            iv = base64.b64decode(data['iv'])
            hmac_key = base64.b64decode(data['hmac_key'])
            salt = base64.b64decode(data['salt'])
            
            if 'generated_password' in data:
                generated_password = base64.b64decode(data['generated_password'])
                return iv, hmac_key, salt, generated_password
            
            return iv, hmac_key, salt, None
            
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid key file format: {e}")

    def enhance_key_generation(self, password: bytes, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Generate a stronger encryption key using Argon2id."""
        if salt is None:
            salt = os.urandom(32)
        
        argon2_hasher = PasswordHasher(
            time_cost=4,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=32,
            type=Type.ID
        )
        
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=argon2_hasher.time_cost,
            memory_cost=argon2_hasher.memory_cost,
            parallelism=argon2_hasher.parallelism,
            hash_len=argon2_hasher.hash_len,
            type=argon2_hasher.type
        )
        
        final_key = hashlib.sha3_256(key).digest()
        return final_key, salt

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt a single block."""
        if len(plaintext) != 16:
            raise ValueError("AES processes 16-byte blocks")
        
        if self.round_keys is None:
            raise ValueError("Round keys must be generated before encryption")
        
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = plaintext[i + 4*j]
        
        state = self._add_round_key(state, self.round_keys[0])
        
        for round_num in range(1, 14):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round_num])
        
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[14])
        
        result = bytearray(16)
        for i in range(4):
            for j in range(4):
                result[i + 4*j] = state[i][j]
        
        return bytes(result)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt a single block."""
        if len(ciphertext) != 16:
            raise ValueError("AES processes 16-byte blocks")
        
        if self.round_keys is None:
            raise ValueError("Round keys must be generated before decryption")
        
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = ciphertext[i + 4*j]
        
        state = self._add_round_key(state, self.round_keys[14])
        
        for round_num in range(13, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[round_num])
            state = self._inv_mix_columns(state)
        
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])
        
        result = bytearray(16)
        for i in range(4):
            for j in range(4):
                result[i + 4*j] = state[i][j]
        
        return bytes(result)

    def encrypt_file_with_password(self, input_path: Union[str, Path], output_path: Union[str, Path] = None, 
                                 user_password: str = None, progress_callback= None) -> Tuple[Path, Path]:
        """Encrypt a file with password and progress tracking."""
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + '.encrypted')
        else:
            output_path = Path(output_path)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        generated_password = None
        if user_password:
            password_bytes = user_password.encode('utf-8')
            readable_password = user_password
        else:
            generated_password, readable_password = self.generate_secure_password()
            password_bytes = generated_password
        
        #self._current_masks = os.urandom(1)[0]

        key, salt = self.enhance_key_generation(password_bytes)
        self.round_keys = self.expand_key(key)
        
        iv = os.urandom(16)
        hmac_key = self._generate_hmac_key()
        
        #key_file = self.save_encryption_data(output_path, iv, hmac_key, salt, generated_password)
        
        total_size = os.path.getsize(input_path)
        processed_size = 0
        encrypted_data = bytearray()
        encrypted_data.extend(salt)
        encrypted_data.extend(iv)
        
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(input_path, 'rb') as infile:
            prev_block = iv
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                
                if len(chunk) % 16 != 0:
                    pad_len = 16 - (len(chunk) % 16)
                    chunk += bytes([pad_len] * pad_len)
                
                for i in range(0, len(chunk), 16):
                    block = bytearray(chunk[i:i+16])
                    for j in range(16):
                        block[j] ^= prev_block[j]
                    
                    encrypted_block = self.encrypt_block(bytes(block))
                    encrypted_data.extend(encrypted_block)
                    prev_block = encrypted_block
                
                    processed_size += len(chunk)
                    if progress_callback and i % 1024==0:
                        # Calculate progress as percentage of file processed (0-100%)
                        progress = int(( i / total_size) * 100)
                        progress_callback(progress)
            
        
        key_file = self.save_encryption_data(output_path, iv, hmac_key, salt, generated_password)   
        hmac_value = self._calculate_hmac(encrypted_data, hmac_key)
        
        
            
        with open(output_path, 'wb') as outfile:
            outfile.write(encrypted_data)
            outfile.write(hmac_value)
        
        
        
        if generated_password:
            print(f"Generated password: {readable_password}")
        
        return output_path, key_file

    def decrypt_file_with_password(self, input_path: Union[str, Path], password: bytes, 
                                 iv: bytes, hmac_key: bytes, salt: bytes,masks:bytes,
                                 output_path: Union[str, Path] = None,
                                 progress_callback: Callable[[int], None] = None) -> Path:
        """Decrypt a file with progress tracking."""
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        if output_path is None:
            if input_path.suffix == '.encrypted':
                output_path = input_path.with_suffix('')
            else:
                output_path = input_path.with_suffix(input_path.suffix + '.decrypted')
        else:
            output_path = Path(output_path)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(input_path, 'rb') as infile:
            file_content = infile.read()
            
            if len(file_content) < 32 + 16 + 32:
                raise ValueError("Invalid encrypted file: too short")
            
            stored_salt = file_content[:32]
            stored_iv = file_content[32:48]
            hmac_value = file_content[-32:]
            encrypted_data = file_content[48:-32]
            self._current_masks = masks
            if not hmac.compare_digest(stored_salt, salt):
                raise ValueError("Salt verification failed")
            if not hmac.compare_digest(stored_iv, iv):
                raise ValueError("IV verification failed")
            if not self._verify_hmac(file_content[:-32], hmac_key, hmac_value):
                raise ValueError("HMAC verification failed")
        
            
            # Fix the check - was checking for _current_mask instead of _current_masks
            if not hasattr(self, '_current_masks') or self._current_masks is None:
                raise ValueError("Missing mask value for decryption")
                
            key, _ = self.enhance_key_generation(password, salt)
            self.round_keys = self.expand_key(key)
            
            prev_block = stored_iv
            decrypted_data = bytearray()
            
            total_blocks = len(encrypted_data) // 16
            processed_blocks = 0
            
            for i in range(0, len(encrypted_data), 16):
                block = encrypted_data[i:i+16]
                decrypted_block = self.decrypt_block(block)
                plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
                decrypted_data.extend(plaintext_block)
                prev_block = block
                
                processed_blocks += 1
                if progress_callback:
                    # Calculate progress as percentage of file processed (0-90%)
                    # Reserve the last 10% for padding verification and file writing
                    progress = min(int((processed_blocks / total_blocks) * 90), 90)
                    progress_callback(progress)
            
            # Update progress to indicate padding verification
            if progress_callback:
                progress_callback(95)
                
            if decrypted_data:
                padding_len = decrypted_data[-1]
                if 1 <= padding_len <= 16:
                    if all(x == padding_len for x in decrypted_data[-padding_len:]):
                        decrypted_data = decrypted_data[:-padding_len]
                    else:
                        raise ValueError("Invalid padding - incorrect password")
            
            # Update progress to indicate file writing
            if progress_callback:
                progress_callback(98)
                
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
            
            # Final progress update to indicate completion
            if progress_callback:
                progress_callback(100)
        
        return output_path
