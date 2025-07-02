#!/usr/bin/env python3
"""
PyPass - Secure Password Manager
Main entry point for the application.
"""
import sys
import os
import tkinter as tk
from tkinter import messagebox

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from pypass.gui.main_window import PyPassGUI
    from pypass.utils.migration import CSVMigration
    from pypass.database.manager import DatabaseManager
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)


def check_legacy_data():
    """Check for legacy CSV data and offer migration."""
    legacy_csv = "src/database.csv"
    if os.path.exists(legacy_csv):
        # Check if we have the modern database
        if not os.path.exists("pypass.db"):
            return legacy_csv
    return None


def migrate_legacy_data(csv_path: str):
    """Migrate legacy CSV data to new encrypted database."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    try:
        if messagebox.askyesno("Legacy Data Found", 
                              "Legacy password data (CSV) was found. "
                              "Would you like to migrate it to the new secure format?\n\n"
                              "This will create a new encrypted vault."):
            
            # Get master password for new vault
            from tkinter import simpledialog
            master_password = simpledialog.askstring("Master Password", 
                                                    "Create a master password for your new secure vault:",
                                                    show='*')
            if not master_password:
                return False
            
            if len(master_password) < 8:
                messagebox.showerror("Error", "Master password must be at least 8 characters long.")
                return False
            
            # Initialize new database
            db_manager = DatabaseManager()
            if not db_manager.initialize_database(master_password):
                messagebox.showerror("Error", "Failed to create new vault.")
                return False
            
            # Migrate data
            migration = CSVMigration(db_manager)
            success, message = migration.migrate_csv_file(csv_path)
            
            db_manager.close()
            
            if success:
                # Backup original CSV
                migration.backup_csv_file(csv_path)
                messagebox.showinfo("Migration Complete", 
                                  f"{message}\n\nOriginal CSV file backed up as {csv_path}.backup")
                return True
            else:
                messagebox.showerror("Migration Failed", message)
                return False
        
        return False
        
    finally:
        root.destroy()


def main():
    """Main application entry point."""
    print("Starting PyPass - Secure Password Manager...")
    
    # Check for legacy data
    legacy_csv = check_legacy_data()
    if legacy_csv:
        print(f"Found legacy data: {legacy_csv}")
        migrate_legacy_data(legacy_csv)
    
    # Start the GUI
    try:
        app = PyPassGUI()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()