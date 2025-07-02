#!/usr/bin/env python3
"""
PyPass Legacy CLI Interface
This is the original basic CLI interface, maintained for backward compatibility.

WARNING: This interface stores passwords in plain text and is deprecated.
Please use the new GUI version by running: python3 main.py

The new version includes:
- AES-256 encryption
- Secure master password
- Modern GUI interface
- Password generation
- Two-factor authentication
- And much more!
"""

import os
import sys

def show_migration_notice():
    """Show migration notice to users."""
    print("=" * 60)
    print("🔓 SECURITY WARNING: Legacy PyPass CLI")
    print("=" * 60)
    print()
    print("You are using the legacy CLI version of PyPass, which stores")
    print("passwords in PLAIN TEXT and is NOT SECURE.")
    print()
    print("🚀 UPGRADE TO PYPASS 2.0 NOW!")
    print()
    print("The new version includes:")
    print("  ✅ AES-256 military-grade encryption")
    print("  ✅ Secure master password protection")
    print("  ✅ Modern GUI interface")
    print("  ✅ Password generator")
    print("  ✅ Two-factor authentication (2FA)")
    print("  ✅ Automatic data migration")
    print("  ✅ Search and categorization")
    print("  ✅ Secure clipboard handling")
    print()
    print("To upgrade, run:")
    print("  python3 main.py")
    print()
    print("Your existing passwords will be automatically migrated")
    print("to the new secure database.")
    print()
    print("=" * 60)
    print()
    
    choice = input("Continue with insecure legacy version? (y/N): ").lower()
    if choice != 'y':
        print("Good choice! Run 'python3 main.py' to start the secure version.")
        sys.exit(0)

def legacy_main():
    """Original PyPass CLI functionality."""
    print("Welcome to PyPass (Legacy CLI)")
    
    while True:
        user_choice = input("Do you want to create a password or read a password? (c/r): ").lower()
        if user_choice in ["c", "r"]:
            break
        print("Invalid choice. Please enter 'c' to create a password or 'r' to read a password.")

    if user_choice == "c":
        app_name = input("Which app are you creating a password for? ")
        name = input("Enter your Email/Username (e.g., your email or username): ")
        password = input("Enter your password (e.g., a strong and unique password): ")
        print("Creating the password...")
        with open("database.csv", "a", encoding="utf-8") as file:  # Use append mode
            file.write(f'"{app_name}","{name}","{password}"\n')
            print("Password created successfully!")        

    elif user_choice == "r":
        print("Reading the Database...")
        try:
            with open("database.csv", "r", encoding="utf-8") as file:
                content = file.read()
                if content.strip() == "":
                    print("No saved passwords found. Please create one first.")
                else:
                    print("Your saved password(s):\n" + content)
        except FileNotFoundError:
            print("Error: No database file found.")

if __name__ == "__main__":
    # Check if this is being run directly or if the new version exists
    if os.path.exists("main.py") and os.path.exists("pypass"):
        show_migration_notice()
    
    legacy_main()



