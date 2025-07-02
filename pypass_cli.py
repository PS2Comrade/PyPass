#!/usr/bin/env python3
"""
PyPass CLI - Command Line Interface for PyPass 2.0
Secure password manager with encryption, suitable for headless environments.
"""
import sys
import os
import getpass
from typing import Optional, List

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pypass.database.manager import DatabaseManager, PasswordEntry
from pypass.core.password_generator import PasswordGenerator
from pypass.core.two_factor import TwoFactorAuth
from pypass.utils.migration import CSVMigration


class PyPassCLI:
    """Command line interface for PyPass."""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.password_generator = PasswordGenerator()
        self.two_factor = TwoFactorAuth()
        self.is_authenticated = False
    
    def run(self):
        """Main CLI loop."""
        print("=" * 50)
        print("🔐 PyPass 2.0 - Secure Password Manager (CLI)")
        print("=" * 50)
        print()
        
        # Check for existing vault
        if not os.path.exists("pypass.db"):
            print("No vault found. Let's create a new one.")
            if not self.create_vault():
                return
        
        # Authenticate
        if not self.authenticate():
            return
        
        print(f"✅ Welcome to your secure vault!")
        print()
        
        # Main menu loop
        while self.is_authenticated:
            self.show_menu()
            choice = input("Enter your choice: ").strip()
            
            if choice == '1':
                self.list_passwords()
            elif choice == '2':
                self.add_password()
            elif choice == '3':
                self.view_password()
            elif choice == '4':
                self.edit_password()
            elif choice == '5':
                self.delete_password()
            elif choice == '6':
                self.search_passwords()
            elif choice == '7':
                self.generate_password()
            elif choice == '8':
                self.import_csv()
            elif choice == '9':
                self.export_backup()
            elif choice == '0':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
            
            print()
    
    def show_menu(self):
        """Display main menu."""
        print("-" * 30)
        print("PYPASS MAIN MENU")
        print("-" * 30)
        print("1. List all passwords")
        print("2. Add new password")
        print("3. View password details")
        print("4. Edit password")
        print("5. Delete password")
        print("6. Search passwords")
        print("7. Generate password")
        print("8. Import from CSV")
        print("9. Export backup")
        print("0. Exit")
        print("-" * 30)
    
    def create_vault(self) -> bool:
        """Create a new vault."""
        print("\n🆕 Creating New Vault")
        print("-" * 20)
        
        while True:
            master_password = getpass.getpass("Create master password (8+ chars): ")
            if len(master_password) < 8:
                print("❌ Password must be at least 8 characters long.")
                continue
            
            confirm_password = getpass.getpass("Confirm master password: ")
            if master_password != confirm_password:
                print("❌ Passwords do not match.")
                continue
            
            break
        
        if self.db_manager.initialize_database(master_password):
            print("✅ Vault created successfully!")
            self.is_authenticated = True
            return True
        else:
            print("❌ Failed to create vault.")
            return False
    
    def authenticate(self) -> bool:
        """Authenticate with master password."""
        print("\n🔓 Unlock Vault")
        print("-" * 15)
        
        for attempt in range(3):
            master_password = getpass.getpass("Enter master password: ")
            
            if self.db_manager.authenticate(master_password):
                self.is_authenticated = True
                return True
            else:
                remaining = 2 - attempt
                if remaining > 0:
                    print(f"❌ Invalid password. {remaining} attempts remaining.")
                else:
                    print("❌ Too many failed attempts. Access denied.")
        
        return False
    
    def list_passwords(self):
        """List all password entries."""
        entries = self.db_manager.get_all_entries()
        
        if not entries:
            print("📝 No passwords stored.")
            return
        
        print(f"\n📋 Password List ({len(entries)} entries)")
        print("-" * 60)
        print(f"{'ID':<4} {'Name':<20} {'Username':<20} {'Category':<10}")
        print("-" * 60)
        
        for i, entry in enumerate(entries, 1):
            print(f"{i:<4} {entry.name[:19]:<20} {entry.username[:19]:<20} {entry.category:<10}")
    
    def add_password(self):
        """Add a new password entry."""
        print("\n➕ Add New Password")
        print("-" * 20)
        
        name = input("Name/Service: ").strip()
        if not name:
            print("❌ Name is required.")
            return
        
        username = input("Username/Email: ").strip()
        if not username:
            print("❌ Username is required.")
            return
        
        # Password options
        print("\nPassword options:")
        print("1. Enter manually")
        print("2. Generate strong password")
        
        choice = input("Choose option (1-2): ").strip()
        
        if choice == "2":
            password = self.password_generator.generate_password(16)
            print(f"Generated password: {password}")
            
            strength, score, criteria = self.password_generator.analyze_password_strength(password)
            print(f"Strength: {self.password_generator.get_strength_description(strength)}")
            
            if input("Use this password? (Y/n): ").lower() in ['', 'y', 'yes']:
                pass  # Use generated password
            else:
                password = getpass.getpass("Enter password manually: ")
        else:
            password = getpass.getpass("Enter password: ")
        
        url = input("URL (optional): ").strip() or None
        category = input("Category (default: General): ").strip() or "General"
        notes = input("Notes (optional): ").strip() or None
        
        if self.db_manager.add_entry(name, username, password, url, category, notes):
            print("✅ Password added successfully!")
        else:
            print("❌ Failed to add password.")
    
    def view_password(self):
        """View password details."""
        entries = self.db_manager.get_all_entries()
        if not entries:
            print("📝 No passwords stored.")
            return
        
        self.list_passwords()
        
        try:
            choice = int(input("\nEnter password ID to view: "))
            if 1 <= choice <= len(entries):
                entry = entries[choice - 1]
                
                print(f"\n📄 Password Details")
                print("-" * 30)
                print(f"Name: {entry.name}")
                print(f"Username: {entry.username}")
                print(f"Password: {'*' * len(entry.password)} (hidden)")
                print(f"URL: {entry.url or 'N/A'}")
                print(f"Category: {entry.category}")
                print(f"Notes: {entry.notes or 'N/A'}")
                print(f"Created: {entry.created_at[:19]}")
                print(f"Modified: {entry.updated_at[:19]}")
                
                if input("\nShow password? (y/N): ").lower() == 'y':
                    print(f"Password: {entry.password}")
                    
                    # Copy to clipboard if possible
                    try:
                        import pyperclip
                        if input("Copy password to clipboard? (y/N): ").lower() == 'y':
                            pyperclip.copy(entry.password)
                            print("✅ Password copied to clipboard!")
                    except ImportError:
                        pass
            else:
                print("❌ Invalid ID.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    def edit_password(self):
        """Edit an existing password."""
        entries = self.db_manager.get_all_entries()
        if not entries:
            print("📝 No passwords stored.")
            return
        
        self.list_passwords()
        
        try:
            choice = int(input("\nEnter password ID to edit: "))
            if 1 <= choice <= len(entries):
                entry = entries[choice - 1]
                
                print(f"\n✏️  Edit Password: {entry.name}")
                print("-" * 30)
                
                new_name = input(f"Name ({entry.name}): ").strip()
                new_username = input(f"Username ({entry.username}): ").strip()
                
                change_password = input("Change password? (y/N): ").lower() == 'y'
                new_password = None
                if change_password:
                    new_password = getpass.getpass("New password: ")
                
                new_url = input(f"URL ({entry.url or 'N/A'}): ").strip()
                new_category = input(f"Category ({entry.category}): ").strip()
                new_notes = input(f"Notes ({entry.notes or 'N/A'}): ").strip()
                
                # Prepare update data
                update_data = {}
                if new_name:
                    update_data['name'] = new_name
                if new_username:
                    update_data['username'] = new_username
                if new_password:
                    update_data['password'] = new_password
                if new_url:
                    update_data['url'] = new_url
                if new_category:
                    update_data['category'] = new_category
                if new_notes:
                    update_data['notes'] = new_notes
                
                if update_data and self.db_manager.update_entry(entry.id, **update_data):
                    print("✅ Password updated successfully!")
                else:
                    print("ℹ️  No changes made.")
            else:
                print("❌ Invalid ID.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    def delete_password(self):
        """Delete a password entry."""
        entries = self.db_manager.get_all_entries()
        if not entries:
            print("📝 No passwords stored.")
            return
        
        self.list_passwords()
        
        try:
            choice = int(input("\nEnter password ID to delete: "))
            if 1 <= choice <= len(entries):
                entry = entries[choice - 1]
                
                confirm = input(f"Delete '{entry.name}'? This cannot be undone! (y/N): ")
                if confirm.lower() == 'y':
                    if self.db_manager.delete_entry(entry.id):
                        print("✅ Password deleted successfully!")
                    else:
                        print("❌ Failed to delete password.")
                else:
                    print("ℹ️  Deletion cancelled.")
            else:
                print("❌ Invalid ID.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    def search_passwords(self):
        """Search password entries."""
        query = input("\n🔍 Enter search term: ").strip()
        if not query:
            return
        
        entries = self.db_manager.search_entries(query)
        
        if not entries:
            print(f"❌ No passwords found matching '{query}'.")
            return
        
        print(f"\n📋 Search Results for '{query}' ({len(entries)} found)")
        print("-" * 60)
        print(f"{'ID':<4} {'Name':<20} {'Username':<20} {'Category':<10}")
        print("-" * 60)
        
        for i, entry in enumerate(entries, 1):
            print(f"{i:<4} {entry.name[:19]:<20} {entry.username[:19]:<20} {entry.category:<10}")
    
    def generate_password(self):
        """Generate a password with options."""
        print("\n🎲 Password Generator")
        print("-" * 20)
        
        try:
            length = int(input("Password length (8-64, default 16): ") or "16")
            length = max(8, min(64, length))
        except ValueError:
            length = 16
        
        include_symbols = input("Include symbols? (Y/n): ").lower() not in ['n', 'no']
        exclude_ambiguous = input("Exclude ambiguous characters (0O1lI)? (y/N): ").lower() in ['y', 'yes']
        
        # Generate multiple options
        print(f"\n🎯 Generated passwords ({length} characters):")
        print("-" * 40)
        
        for i in range(5):
            password = self.password_generator.generate_password(
                length=length,
                use_symbols=include_symbols,
                exclude_ambiguous=exclude_ambiguous
            )
            
            strength, score, criteria = self.password_generator.analyze_password_strength(password)
            strength_desc = self.password_generator.get_strength_description(strength)
            
            print(f"{i+1}. {password} ({strength_desc})")
        
        # Generate memorable option
        memorable = self.password_generator.generate_memorable_password()
        strength, score, criteria = self.password_generator.analyze_password_strength(memorable)
        strength_desc = self.password_generator.get_strength_description(strength)
        print(f"6. {memorable} (Memorable - {strength_desc})")
        
        # Copy option
        try:
            import pyperclip
            choice = input("\nCopy password to clipboard (1-6): ").strip()
            if choice in ['1', '2', '3', '4', '5']:
                # Would need to regenerate or store the passwords
                print("ℹ️  Feature requires storing generated passwords.")
            elif choice == '6':
                pyperclip.copy(memorable)
                print("✅ Memorable password copied to clipboard!")
        except ImportError:
            print("ℹ️  Install 'pyperclip' for clipboard functionality.")
    
    def import_csv(self):
        """Import passwords from CSV file."""
        csv_path = input("\n📥 Enter path to CSV file: ").strip()
        
        if not os.path.exists(csv_path):
            print(f"❌ File not found: {csv_path}")
            return
        
        migration = CSVMigration(self.db_manager)
        success, message = migration.migrate_csv_file(csv_path)
        
        if success:
            print(f"✅ {message}")
            
            # Backup original
            if input("Backup original CSV file? (Y/n): ").lower() not in ['n', 'no']:
                migration.backup_csv_file(csv_path)
                print(f"✅ Original file backed up as {csv_path}.backup")
        else:
            print(f"❌ {message}")
    
    def export_backup(self):
        """Export encrypted backup."""
        backup_path = input("\n💾 Enter backup file path (default: pypass_backup.backup): ").strip()
        if not backup_path:
            backup_path = "pypass_backup.backup"
        
        export_password = getpass.getpass("Enter password for backup encryption: ")
        if not export_password:
            print("❌ Backup password is required.")
            return
        
        backup_data = self.db_manager.export_data(export_password)
        if backup_data:
            try:
                with open(backup_path, 'w') as f:
                    f.write(backup_data)
                print(f"✅ Backup saved to: {backup_path}")
            except Exception as e:
                print(f"❌ Failed to save backup: {e}")
        else:
            print("❌ Failed to create backup.")


def main():
    """Main entry point."""
    try:
        cli = PyPassCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()