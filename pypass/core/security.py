"""
Core security utilities for PyPass password manager.
Implements AES-256 encryption, PBKDF2 key derivation, and secure memory handling.
"""
import os
import hashlib
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


class SecurityManager:
    """Handles all cryptographic operations for PyPass."""
    
    def __init__(self):
        self.backend = default_backend()
        self.iterations = 100000  # PBKDF2 iterations
        
    def generate_salt(self, length: int = 32) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(length)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_data(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        Returns (encrypted_data, nonce).
        """
        # Generate a random nonce for GCM
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        
        # Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Combine ciphertext with auth tag
        encrypted_data = ciphertext + encryptor.tag
        
        return encrypted_data, nonce
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        """
        # Split ciphertext and auth tag
        ciphertext = encrypted_data[:-16]  # All but last 16 bytes
        tag = encrypted_data[-16:]  # Last 16 bytes are the auth tag
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        
        # Decrypt
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt_string(self, plaintext: str, password: str) -> str:
        """
        Encrypt a string with a password and return base64-encoded result.
        Format: base64(salt + nonce + encrypted_data)
        """
        # Generate salt and derive key
        salt = self.generate_salt()
        key = self.derive_key(password, salt)
        
        # Encrypt data
        data = plaintext.encode('utf-8')
        encrypted_data, nonce = self.encrypt_data(data, key)
        
        # Combine salt + nonce + encrypted_data
        combined = salt + nonce + encrypted_data
        
        # Return base64 encoded
        return base64.b64encode(combined).decode('ascii')
    
    def decrypt_string(self, encrypted_b64: str, password: str) -> str:
        """
        Decrypt a base64-encoded encrypted string with a password.
        """
        # Decode from base64
        combined = base64.b64decode(encrypted_b64.encode('ascii'))
        
        # Extract components
        salt = combined[:32]  # First 32 bytes
        nonce = combined[32:44]  # Next 12 bytes
        encrypted_data = combined[44:]  # Remaining bytes
        
        # Derive key
        key = self.derive_key(password, salt)
        
        # Decrypt
        plaintext_bytes = self.decrypt_data(encrypted_data, key, nonce)
        
        return plaintext_bytes.decode('utf-8')
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify a password against a stored hash."""
        try:
            # Extract salt from stored hash (first 64 chars are base64-encoded salt)
            salt_b64 = stored_hash[:44]  # Base64 encoding of 32 bytes
            salt = base64.b64decode(salt_b64.encode('ascii'))
            
            # Hash the provided password with the same salt
            password_hash = self.hash_password(password, salt)
            
            return password_hash == stored_hash
        except Exception:
            return False
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> str:
        """
        Hash a password for storage.
        Returns base64(salt) + base64(hash).
        """
        if salt is None:
            salt = self.generate_salt()
        
        # Derive key (which serves as our hash)
        key = self.derive_key(password, salt)
        
        # Return salt + hash, both base64 encoded
        salt_b64 = base64.b64encode(salt).decode('ascii')
        hash_b64 = base64.b64encode(key).decode('ascii')
        
        return salt_b64 + hash_b64


class SecureString:
    """A string that attempts to minimize exposure in memory."""
    
    def __init__(self, value: str):
        self._value = value
    
    def get(self) -> str:
        """Get the string value."""
        return self._value
    
    def clear(self):
        """Clear the string from memory (best effort)."""
        if self._value:
            # Overwrite with zeros
            self._value = '\0' * len(self._value)
            self._value = ''
    
    def __del__(self):
        """Clear on deletion."""
        self.clear()
    
    def __str__(self):
        return "SecureString(***)"
    
    def __repr__(self):
        return "SecureString(***)"