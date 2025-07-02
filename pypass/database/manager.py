"""
Encrypted SQLite database manager for PyPass.
Handles secure storage and retrieval of password entries.
"""
import sqlite3
import json
import os
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from ..core.security import SecurityManager


@dataclass
class PasswordEntry:
    """Represents a password entry in the database."""
    id: Optional[int]
    name: str
    username: str
    password: str
    url: Optional[str]
    category: str
    notes: Optional[str]
    created_at: str
    updated_at: str
    accessed_at: Optional[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PasswordEntry':
        """Create from dictionary."""
        return cls(**data)


class DatabaseManager:
    """Manages encrypted SQLite database operations."""
    
    def __init__(self, db_path: str = "pypass.db"):
        self.db_path = db_path
        self.security = SecurityManager()
        self._master_key = None
        self._connection = None
        
    def initialize_database(self, master_password: str) -> bool:
        """
        Initialize the database with a master password.
        Creates the database file and tables if they don't exist.
        """
        try:
            # Derive master key
            self._master_key = self._derive_master_key(master_password)
            
            # Create database connection
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
            
            # Create tables
            self._create_tables()
            
            # Store master password verification
            self._store_master_verification(master_password)
            
            return True
        except Exception as e:
            print(f"Error initializing database: {e}")
            return False
    
    def authenticate(self, master_password: str) -> bool:
        """Authenticate with master password and unlock database."""
        try:
            if not os.path.exists(self.db_path):
                return False
            
            # Connect to database
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
            
            # Verify master password
            if not self._verify_master_password(master_password):
                return False
            
            # Derive master key
            self._master_key = self._derive_master_key(master_password)
            
            return True
        except Exception as e:
            print(f"Error authenticating: {e}")
            return False
    
    def close(self):
        """Close database connection and clear master key."""
        if self._connection:
            self._connection.close()
            self._connection = None
        self._master_key = None
    
    def add_entry(self, name: str, username: str, password: str, 
                  url: Optional[str] = None, category: str = "General", 
                  notes: Optional[str] = None) -> bool:
        """Add a new password entry."""
        try:
            if not self._master_key:
                return False
            
            now = datetime.now().isoformat()
            
            # Create entry
            entry = PasswordEntry(
                id=None,
                name=name,
                username=username,
                password=password,
                url=url,
                category=category,
                notes=notes,
                created_at=now,
                updated_at=now,
                accessed_at=None
            )
            
            # Encrypt sensitive data
            encrypted_data = self._encrypt_entry_data(entry)
            
            # Insert into database
            cursor = self._connection.cursor()
            cursor.execute("""
                INSERT INTO password_entries 
                (encrypted_data, category, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            """, (encrypted_data, category, now, now))
            
            self._connection.commit()
            return True
            
        except Exception as e:
            print(f"Error adding entry: {e}")
            return False
    
    def get_all_entries(self) -> List[PasswordEntry]:
        """Retrieve all password entries."""
        try:
            if not self._master_key:
                return []
            
            cursor = self._connection.cursor()
            cursor.execute("SELECT * FROM password_entries ORDER BY updated_at DESC")
            
            entries = []
            for row in cursor.fetchall():
                try:
                    entry = self._decrypt_entry_data(row)
                    if entry:
                        entries.append(entry)
                except Exception as e:
                    print(f"Error decrypting entry {row['id']}: {e}")
                    continue
            
            return entries
            
        except Exception as e:
            print(f"Error retrieving entries: {e}")
            return []
    
    def get_entry_by_id(self, entry_id: int) -> Optional[PasswordEntry]:
        """Retrieve a specific entry by ID."""
        try:
            if not self._master_key:
                return None
            
            cursor = self._connection.cursor()
            cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            
            if row:
                # Update access time
                self._update_access_time(entry_id)
                return self._decrypt_entry_data(row)
            
            return None
            
        except Exception as e:
            print(f"Error retrieving entry: {e}")
            return None
    
    def update_entry(self, entry_id: int, **kwargs) -> bool:
        """Update an existing entry."""
        try:
            if not self._master_key:
                return False
            
            # Get existing entry
            entry = self.get_entry_by_id(entry_id)
            if not entry:
                return False
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(entry, key):
                    setattr(entry, key, value)
            
            entry.updated_at = datetime.now().isoformat()
            
            # Encrypt and store
            encrypted_data = self._encrypt_entry_data(entry)
            
            cursor = self._connection.cursor()
            cursor.execute("""
                UPDATE password_entries 
                SET encrypted_data = ?, category = ?, updated_at = ?
                WHERE id = ?
            """, (encrypted_data, entry.category, entry.updated_at, entry_id))
            
            self._connection.commit()
            return True
            
        except Exception as e:
            print(f"Error updating entry: {e}")
            return False
    
    def delete_entry(self, entry_id: int) -> bool:
        """Delete an entry."""
        try:
            cursor = self._connection.cursor()
            cursor.execute("DELETE FROM password_entries WHERE id = ?", (entry_id,))
            self._connection.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            print(f"Error deleting entry: {e}")
            return False
    
    def search_entries(self, query: str) -> List[PasswordEntry]:
        """Search entries by name, username, or URL."""
        entries = self.get_all_entries()
        query_lower = query.lower()
        
        filtered = []
        for entry in entries:
            if (query_lower in entry.name.lower() or
                query_lower in entry.username.lower() or
                (entry.url and query_lower in entry.url.lower()) or
                query_lower in entry.category.lower()):
                filtered.append(entry)
        
        return filtered
    
    def get_categories(self) -> List[str]:
        """Get all unique categories."""
        entries = self.get_all_entries()
        categories = set(entry.category for entry in entries)
        return sorted(list(categories))
    
    def export_data(self, export_password: str) -> Optional[str]:
        """Export all data in encrypted JSON format."""
        try:
            entries = self.get_all_entries()
            data = {
                "version": "1.0",
                "export_date": datetime.now().isoformat(),
                "entries": [entry.to_dict() for entry in entries]
            }
            
            json_data = json.dumps(data, indent=2)
            encrypted_data = self.security.encrypt_string(json_data, export_password)
            
            return encrypted_data
            
        except Exception as e:
            print(f"Error exporting data: {e}")
            return None
    
    def import_data(self, encrypted_data: str, import_password: str) -> bool:
        """Import data from encrypted JSON format."""
        try:
            # Decrypt data
            json_data = self.security.decrypt_string(encrypted_data, import_password)
            data = json.loads(json_data)
            
            # Import entries
            for entry_data in data.get("entries", []):
                entry_data.pop("id", None)  # Remove ID to create new entries
                entry = PasswordEntry.from_dict(entry_data)
                
                self.add_entry(
                    name=entry.name,
                    username=entry.username,
                    password=entry.password,
                    url=entry.url,
                    category=entry.category,
                    notes=entry.notes
                )
            
            return True
            
        except Exception as e:
            print(f"Error importing data: {e}")
            return False
    
    def _create_tables(self):
        """Create database tables."""
        cursor = self._connection.cursor()
        
        # Main password entries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_data TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'General',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # Master password verification table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master_auth (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                entry_id INTEGER,
                timestamp TEXT NOT NULL
            )
        """)
        
        self._connection.commit()
    
    def _derive_master_key(self, master_password: str) -> bytes:
        """Derive master key from password."""
        # Use a fixed salt for master key derivation
        # In practice, you might want to store this salt separately
        salt = b"PyPass_Master_Salt_2024"
        return self.security.derive_key(master_password, salt)
    
    def _store_master_verification(self, master_password: str):
        """Store master password verification hash."""
        password_hash = self.security.hash_password(master_password)
        
        cursor = self._connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO master_auth (id, password_hash, created_at)
            VALUES (1, ?, ?)
        """, (password_hash, datetime.now().isoformat()))
        
        self._connection.commit()
    
    def _verify_master_password(self, master_password: str) -> bool:
        """Verify master password against stored hash."""
        cursor = self._connection.cursor()
        cursor.execute("SELECT password_hash FROM master_auth WHERE id = 1")
        row = cursor.fetchone()
        
        if not row:
            return False
        
        return self.security.verify_password(master_password, row[0])
    
    def _encrypt_entry_data(self, entry: PasswordEntry) -> str:
        """Encrypt entry data for storage."""
        # Convert to JSON
        data = entry.to_dict()
        data.pop("id", None)  # Don't encrypt the ID
        
        json_data = json.dumps(data)
        
        # Encrypt with master key
        # We'll use the SecurityManager's string encryption with a derived password
        password = self._master_key.hex()
        
        return self.security.encrypt_string(json_data, password)
    
    def _decrypt_entry_data(self, row) -> Optional[PasswordEntry]:
        """Decrypt entry data from storage."""
        try:
            # Decrypt with master key
            password = self._master_key.hex()
            json_data = self.security.decrypt_string(row["encrypted_data"], password)
            
            # Parse JSON
            data = json.loads(json_data)
            data["id"] = row["id"]  # Add the ID back
            
            return PasswordEntry.from_dict(data)
            
        except Exception as e:
            print(f"Error decrypting entry data: {e}")
            return None
    
    def _update_access_time(self, entry_id: int):
        """Update the access time for an entry."""
        try:
            entry = self.get_entry_by_id(entry_id)
            if entry:
                entry.accessed_at = datetime.now().isoformat()
                encrypted_data = self._encrypt_entry_data(entry)
                
                cursor = self._connection.cursor()
                cursor.execute("""
                    UPDATE password_entries 
                    SET encrypted_data = ? 
                    WHERE id = ?
                """, (encrypted_data, entry_id))
                
                self._connection.commit()
                
        except Exception:
            pass  # Ignore access time update errors