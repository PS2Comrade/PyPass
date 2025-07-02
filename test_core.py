#!/usr/bin/env python3
"""
Test script for PyPass core functionality.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pypass.core.security import SecurityManager, SecureString
from pypass.core.password_generator import PasswordGenerator, PasswordStrength
from pypass.core.two_factor import TwoFactorAuth
from pypass.database.manager import DatabaseManager, PasswordEntry


def test_security():
    """Test security functions."""
    print("Testing Security Manager...")
    
    security = SecurityManager()
    
    # Test password hashing
    password = "test_master_password_123"
    hash1 = security.hash_password(password)
    hash2 = security.hash_password(password)
    
    print(f"Password hash 1: {hash1[:50]}...")
    print(f"Password hash 2: {hash2[:50]}...")
    print(f"Hashes different (good): {hash1 != hash2}")
    
    # Test password verification
    print(f"Password verification: {security.verify_password(password, hash1)}")
    print(f"Wrong password verification: {security.verify_password('wrong', hash1)}")
    
    # Test string encryption
    plaintext = "This is a secret message!"
    encrypted = security.encrypt_string(plaintext, password)
    decrypted = security.decrypt_string(encrypted, password)
    
    print(f"Original: {plaintext}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Encryption/Decryption works: {plaintext == decrypted}")
    
    print()


def test_password_generator():
    """Test password generation."""
    print("Testing Password Generator...")
    
    generator = PasswordGenerator()
    
    # Test different password types
    passwords = [
        generator.generate_password(12, use_symbols=False),
        generator.generate_password(16, exclude_ambiguous=True),
        generator.generate_password(20),
        generator.generate_memorable_password(4)
    ]
    
    for i, pwd in enumerate(passwords, 1):
        strength, score, criteria = generator.analyze_password_strength(pwd)
        print(f"Password {i}: {pwd}")
        print(f"  Strength: {generator.get_strength_description(strength)} (Score: {score})")
        print(f"  Criteria: {criteria}")
        print()


def test_database():
    """Test database operations."""
    print("Testing Database Manager...")
    
    # Remove test database if it exists
    test_db = "/tmp/test_pypass.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    master_password = "test_master_123"
    
    # Initialize database
    print(f"Initializing database: {db.initialize_database(master_password)}")
    
    # Test authentication
    db.close()
    print(f"Authentication: {db.authenticate(master_password)}")
    
    # Add test entries
    print(f"Adding entry 1: {db.add_entry('Gmail', 'user@gmail.com', 'password123', 'https://gmail.com', 'Email')}")
    print(f"Adding entry 2: {db.add_entry('Facebook', 'myuser', 'fb_password', 'https://facebook.com', 'Social')}")
    
    # Retrieve entries
    entries = db.get_all_entries()
    print(f"Retrieved {len(entries)} entries:")
    for entry in entries:
        print(f"  {entry.name}: {entry.username} (Category: {entry.category})")
    
    # Test search
    search_results = db.search_entries("gmail")
    print(f"Search for 'gmail': {len(search_results)} results")
    
    # Test categories
    categories = db.get_categories()
    print(f"Categories: {categories}")
    
    db.close()
    print()


def test_two_factor():
    """Test 2FA functionality."""
    print("Testing Two-Factor Authentication...")
    
    tfa = TwoFactorAuth()
    
    # Generate secret
    secret = tfa.generate_secret()
    print(f"Generated secret: {tfa.format_secret_for_display(secret)}")
    
    # Generate current token
    current_token = tfa.get_current_token(secret)
    print(f"Current token: {current_token}")
    
    # Verify token
    print(f"Token verification: {tfa.verify_token(secret, current_token)}")
    print(f"Wrong token verification: {tfa.verify_token(secret, '000000')}")
    
    # Generate backup codes
    backup_codes = tfa.get_backup_codes(5)
    print(f"Backup codes: {backup_codes}")
    
    print()


if __name__ == "__main__":
    test_security()
    test_password_generator()
    test_database()
    test_two_factor()
    print("All tests completed!")