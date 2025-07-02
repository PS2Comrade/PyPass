"""
CSV migration utility for converting legacy PyPass data.
"""
import csv
import os
from typing import List, Dict, Optional, Tuple
from ..database.manager import DatabaseManager, PasswordEntry
from datetime import datetime


class CSVMigration:
    """Handles migration from CSV to encrypted database."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
    
    def migrate_csv_file(self, csv_path: str) -> Tuple[bool, str]:
        """
        Migrate passwords from CSV file to encrypted database.
        
        Returns:
            (success, message)
        """
        try:
            if not os.path.exists(csv_path):
                return False, f"CSV file not found: {csv_path}"
            
            entries = self.parse_csv_file(csv_path)
            if not entries:
                return False, "No valid entries found in CSV file"
            
            success_count = 0
            error_count = 0
            
            for entry in entries:
                try:
                    if self.db_manager.add_entry(
                        name=entry.get("name", entry.get("app_name", "Unknown")),
                        username=entry.get("username", entry.get("name", "")),
                        password=entry.get("password", ""),
                        url=entry.get("url", ""),
                        category="Migrated",
                        notes=f"Migrated from CSV on {datetime.now().strftime('%Y-%m-%d')}"
                    ):
                        success_count += 1
                    else:
                        error_count += 1
                except Exception as e:
                    print(f"Error migrating entry: {e}")
                    error_count += 1
            
            message = f"Migration completed: {success_count} entries migrated"
            if error_count > 0:
                message += f", {error_count} errors"
            
            return success_count > 0, message
            
        except Exception as e:
            return False, f"Migration failed: {str(e)}"
    
    def parse_csv_file(self, csv_path: str) -> List[Dict[str, str]]:
        """Parse CSV file and extract password entries."""
        entries = []
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as file:
                # Try to detect the CSV format
                sample = file.read(1024)
                file.seek(0)
                
                # Check if it's the old PyPass format or browser export format
                if '"url","username","password"' in sample:
                    # Browser export format
                    entries = self._parse_browser_csv(file)
                else:
                    # Try PyPass format or generic CSV
                    entries = self._parse_pypass_csv(file)
                    
        except Exception as e:
            print(f"Error parsing CSV file: {e}")
        
        return entries
    
    def _parse_browser_csv(self, file) -> List[Dict[str, str]]:
        """Parse browser password export CSV format."""
        entries = []
        
        try:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("username") and row.get("password"):
                    entries.append({
                        "name": row.get("url", "").replace("https://", "").replace("http://", "").split("/")[0],
                        "username": row.get("username", ""),
                        "password": row.get("password", ""),
                        "url": row.get("url", "")
                    })
        except Exception as e:
            print(f"Error parsing browser CSV: {e}")
        
        return entries
    
    def _parse_pypass_csv(self, file) -> List[Dict[str, str]]:
        """Parse PyPass legacy CSV format."""
        entries = []
        
        try:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 3 and row[0] and row[1] and row[2]:
                    # PyPass format: app_name, username, password
                    entries.append({
                        "name": row[0].strip(),
                        "username": row[1].strip(),
                        "password": row[2].strip(),
                        "url": "",
                        "app_name": row[0].strip()
                    })
        except Exception as e:
            print(f"Error parsing PyPass CSV: {e}")
        
        return entries
    
    def backup_csv_file(self, csv_path: str) -> bool:
        """Create a backup of the original CSV file."""
        try:
            import shutil
            backup_path = csv_path + ".backup"
            shutil.copy2(csv_path, backup_path)
            return True
        except Exception as e:
            print(f"Error creating backup: {e}")
            return False