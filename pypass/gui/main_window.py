"""
Main PyPass GUI application using Tkinter.
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import threading
import os
import sys
from typing import Optional, List
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pypass.database.manager import DatabaseManager, PasswordEntry
from pypass.core.password_generator import PasswordGenerator, PasswordStrength
from pypass.core.two_factor import TwoFactorAuth
from pypass.core.security import SecureString
from pypass.utils.migration import CSVMigration


class PyPassGUI:
    """Main PyPass GUI application."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PyPass - Secure Password Manager")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Initialize managers
        self.db_manager = DatabaseManager()
        self.password_generator = PasswordGenerator()
        self.two_factor = TwoFactorAuth()
        
        # State variables
        self.is_authenticated = False
        self.current_theme = "light"
        self.session_timer = None
        self.auto_lock_minutes = 15
        
        # GUI components
        self.main_frame = None
        self.login_frame = None
        self.password_list = None
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar()
        
        # Setup GUI
        self.setup_styles()
        self.create_login_interface()
        self.setup_menu()
        
        # Center window
        self.center_window()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_styles(self):
        """Setup themes and styles."""
        self.style = ttk.Style()
        
        # Configure light theme
        self.light_theme = {
            'bg': '#FFFFFF',
            'fg': '#000000',
            'select_bg': '#0078D4',
            'select_fg': '#FFFFFF',
            'entry_bg': '#FFFFFF',
            'button_bg': '#F0F0F0'
        }
        
        # Configure dark theme
        self.dark_theme = {
            'bg': '#2D2D30',
            'fg': '#FFFFFF',
            'select_bg': '#0078D4',
            'select_fg': '#FFFFFF',
            'entry_bg': '#3C3C3C',
            'button_bg': '#404040'
        }
        
        self.apply_theme()
    
    def apply_theme(self):
        """Apply current theme."""
        theme = self.light_theme if self.current_theme == "light" else self.dark_theme
        
        self.root.configure(bg=theme['bg'])
        
        # Configure ttk styles
        self.style.configure('TFrame', background=theme['bg'])
        self.style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        self.style.configure('TButton', background=theme['button_bg'])
        self.style.configure('TEntry', fieldbackground=theme['entry_bg'])
        self.style.configure('Treeview', background=theme['bg'], foreground=theme['fg'])
    
    def toggle_theme(self):
        """Toggle between light and dark themes."""
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self.apply_theme()
    
    def center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_menu(self):
        """Setup application menu."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Import CSV...", command=self.import_csv)
        file_menu.add_command(label="Export Backup...", command=self.export_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Lock Vault", command=self.lock_vault)
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Password Generator", command=self.open_password_generator)
        tools_menu.add_command(label="Setup 2FA", command=self.setup_2fa)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_login_interface(self):
        """Create the login interface."""
        if self.main_frame:
            self.main_frame.destroy()
        
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Center the login form
        login_container = ttk.Frame(self.login_frame)
        login_container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Title
        title_label = ttk.Label(login_container, text="PyPass", font=("Arial", 24, "bold"))
        title_label.pack(pady=(0, 10))
        
        subtitle_label = ttk.Label(login_container, text="Secure Password Manager", font=("Arial", 12))
        subtitle_label.pack(pady=(0, 30))
        
        # Master password entry
        ttk.Label(login_container, text="Master Password:").pack(anchor=tk.W)
        self.master_password_entry = ttk.Entry(login_container, show="*", width=30)
        self.master_password_entry.pack(pady=(5, 10))
        self.master_password_entry.bind("<Return>", lambda e: self.authenticate())
        
        # Buttons
        button_frame = ttk.Frame(login_container)
        button_frame.pack(pady=10)
        
        login_btn = ttk.Button(button_frame, text="Unlock Vault", command=self.authenticate)
        login_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        create_btn = ttk.Button(button_frame, text="Create New Vault", command=self.create_new_vault)
        create_btn.pack(side=tk.LEFT)
        
        # Focus on password entry
        self.master_password_entry.focus()
    
    def create_main_interface(self):
        """Create the main password management interface."""
        if self.login_frame:
            self.login_frame.destroy()
        
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top toolbar
        self.create_toolbar()
        
        # Search and filter frame
        self.create_search_frame()
        
        # Password list
        self.create_password_list()
        
        # Bottom buttons
        self.create_action_buttons()
        
        # Load passwords
        self.refresh_password_list()
        
        # Start session timer
        self.start_session_timer()
    
    def create_toolbar(self):
        """Create top toolbar."""
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(toolbar, text="PyPass - Password Vault", font=("Arial", 16, "bold"))
        title_label.pack(side=tk.LEFT)
        
        # Lock button
        lock_btn = ttk.Button(toolbar, text="Lock Vault", command=self.lock_vault)
        lock_btn.pack(side=tk.RIGHT)
    
    def create_search_frame(self):
        """Create search and filter controls."""
        search_frame = ttk.Frame(self.main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(5, 20))
        self.search_var.trace("w", self.on_search_change)
        
        # Category filter
        ttk.Label(search_frame, text="Category:").pack(side=tk.LEFT)
        self.category_combo = ttk.Combobox(search_frame, textvariable=self.category_var, 
                                          state="readonly", width=15)
        self.category_combo.pack(side=tk.LEFT, padx=(5, 0))
        self.category_var.trace("w", self.on_search_change)
    
    def create_password_list(self):
        """Create password list treeview."""
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview with scrollbar
        columns = ("Name", "Username", "Category", "URL", "Modified")
        self.password_list = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.password_list.heading("Name", text="Name")
        self.password_list.heading("Username", text="Username")
        self.password_list.heading("Category", text="Category")
        self.password_list.heading("URL", text="URL")
        self.password_list.heading("Modified", text="Modified")
        
        self.password_list.column("Name", width=200)
        self.password_list.column("Username", width=200)
        self.password_list.column("Category", width=100)
        self.password_list.column("URL", width=250)
        self.password_list.column("Modified", width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_list.yview)
        self.password_list.configure(yscrollcommand=scrollbar.set)
        
        # Pack
        self.password_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.password_list.bind("<Double-1>", self.on_password_double_click)
        self.password_list.bind("<Button-3>", self.show_context_menu)  # Right click
    
    def create_action_buttons(self):
        """Create action buttons."""
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Add Password", command=self.add_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Edit", command=self.edit_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Delete", command=self.delete_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Copy Password", command=self.copy_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Copy Username", command=self.copy_username).pack(side=tk.LEFT, padx=(0, 5))
        
        # Refresh button on the right
        ttk.Button(button_frame, text="Refresh", command=self.refresh_password_list).pack(side=tk.RIGHT)
    
    def authenticate(self):
        """Authenticate with master password."""
        master_password = self.master_password_entry.get()
        
        if not master_password:
            messagebox.showerror("Error", "Please enter your master password.")
            return
        
        # Clear the entry for security
        self.master_password_entry.delete(0, tk.END)
        
        # Try to authenticate
        if self.db_manager.authenticate(master_password):
            self.is_authenticated = True
            self.create_main_interface()
        else:
            messagebox.showerror("Authentication Failed", "Invalid master password.")
            self.master_password_entry.focus()
    
    def create_new_vault(self):
        """Create a new password vault."""
        dialog = NewVaultDialog(self.root)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            master_password, confirm_password = dialog.result
            
            if master_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            
            if len(master_password) < 8:
                messagebox.showerror("Error", "Master password must be at least 8 characters long.")
                return
            
            # Check if database exists
            if os.path.exists("pypass.db"):
                if not messagebox.askyesno("Confirm", 
                                         "A vault already exists. Creating a new vault will overwrite it. Continue?"):
                    return
            
            # Create new vault
            if self.db_manager.initialize_database(master_password):
                messagebox.showinfo("Success", "New vault created successfully!")
                self.is_authenticated = True
                self.create_main_interface()
            else:
                messagebox.showerror("Error", "Failed to create new vault.")
    
    def lock_vault(self):
        """Lock the vault and return to login screen."""
        self.is_authenticated = False
        self.db_manager.close()
        self.stop_session_timer()
        self.create_login_interface()
    
    def refresh_password_list(self):
        """Refresh the password list."""
        if not self.is_authenticated:
            return
        
        # Clear existing items
        for item in self.password_list.get_children():
            self.password_list.delete(item)
        
        # Get entries
        entries = self.get_filtered_entries()
        
        # Populate list
        for entry in entries:
            # Format date
            try:
                date_obj = datetime.fromisoformat(entry.updated_at)
                formatted_date = date_obj.strftime("%Y-%m-%d")
            except:
                formatted_date = entry.updated_at[:10] if entry.updated_at else ""
            
            self.password_list.insert("", tk.END, values=(
                entry.name,
                entry.username,
                entry.category,
                entry.url or "",
                formatted_date
            ), tags=(str(entry.id),))
        
        # Update category filter
        self.update_category_filter()
    
    def get_filtered_entries(self) -> List[PasswordEntry]:
        """Get filtered password entries."""
        entries = self.db_manager.get_all_entries()
        
        # Apply search filter
        search_term = self.search_var.get().lower()
        if search_term:
            entries = [e for e in entries if (
                search_term in e.name.lower() or
                search_term in e.username.lower() or
                search_term in (e.url or "").lower() or
                search_term in e.category.lower()
            )]
        
        # Apply category filter
        category = self.category_var.get()
        if category and category != "All":
            entries = [e for e in entries if e.category == category]
        
        return entries
    
    def update_category_filter(self):
        """Update category filter dropdown."""
        categories = ["All"] + self.db_manager.get_categories()
        current_value = self.category_var.get()
        
        self.category_combo['values'] = categories
        
        # Keep current selection if still valid
        if current_value not in categories:
            self.category_var.set("All")
    
    def on_search_change(self, *args):
        """Handle search/filter changes."""
        self.refresh_password_list()
    
    def get_selected_entry_id(self) -> Optional[int]:
        """Get the ID of the selected entry."""
        selection = self.password_list.selection()
        if not selection:
            return None
        
        item = self.password_list.item(selection[0])
        tags = item.get('tags', [])
        
        if tags:
            try:
                return int(tags[0])
            except ValueError:
                return None
        
        return None
    
    def add_password(self):
        """Add a new password entry."""
        dialog = PasswordDialog(self.root, "Add Password")
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            entry_data = dialog.result
            if self.db_manager.add_entry(**entry_data):
                self.refresh_password_list()
                messagebox.showinfo("Success", "Password added successfully!")
            else:
                messagebox.showerror("Error", "Failed to add password.")
    
    def edit_password(self):
        """Edit selected password entry."""
        entry_id = self.get_selected_entry_id()
        if not entry_id:
            messagebox.showwarning("No Selection", "Please select a password to edit.")
            return
        
        entry = self.db_manager.get_entry_by_id(entry_id)
        if not entry:
            messagebox.showerror("Error", "Failed to load entry.")
            return
        
        dialog = PasswordDialog(self.root, "Edit Password", entry)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            if self.db_manager.update_entry(entry_id, **dialog.result):
                self.refresh_password_list()
                messagebox.showinfo("Success", "Password updated successfully!")
            else:
                messagebox.showerror("Error", "Failed to update password.")
    
    def delete_password(self):
        """Delete selected password entry."""
        entry_id = self.get_selected_entry_id()
        if not entry_id:
            messagebox.showwarning("No Selection", "Please select a password to delete.")
            return
        
        entry = self.db_manager.get_entry_by_id(entry_id)
        if not entry:
            return
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Are you sure you want to delete '{entry.name}'?"):
            if self.db_manager.delete_entry(entry_id):
                self.refresh_password_list()
                messagebox.showinfo("Success", "Password deleted successfully!")
            else:
                messagebox.showerror("Error", "Failed to delete password.")
    
    def copy_password(self):
        """Copy password to clipboard."""
        entry_id = self.get_selected_entry_id()
        if not entry_id:
            messagebox.showwarning("No Selection", "Please select a password to copy.")
            return
        
        entry = self.db_manager.get_entry_by_id(entry_id)
        if entry:
            self.copy_to_clipboard(entry.password)
            messagebox.showinfo("Copied", "Password copied to clipboard.")
    
    def copy_username(self):
        """Copy username to clipboard."""
        entry_id = self.get_selected_entry_id()
        if not entry_id:
            messagebox.showwarning("No Selection", "Please select a username to copy.")
            return
        
        entry = self.db_manager.get_entry_by_id(entry_id)
        if entry:
            self.copy_to_clipboard(entry.username)
            messagebox.showinfo("Copied", "Username copied to clipboard.")
    
    def copy_to_clipboard(self, text: str):
        """Copy text to clipboard with auto-clear after 30 seconds."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        
        # Schedule clipboard clear
        self.root.after(30000, self.clear_clipboard)  # 30 seconds
    
    def clear_clipboard(self):
        """Clear clipboard for security."""
        try:
            self.root.clipboard_clear()
        except:
            pass  # Ignore errors if window is closed
    
    def on_password_double_click(self, event):
        """Handle double-click on password entry."""
        self.edit_password()
    
    def show_context_menu(self, event):
        """Show context menu on right-click."""
        # Select the item under cursor
        item = self.password_list.identify_row(event.y)
        if item:
            self.password_list.selection_set(item)
            
            # Create context menu
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="Copy Password", command=self.copy_password)
            context_menu.add_command(label="Copy Username", command=self.copy_username)
            context_menu.add_separator()
            context_menu.add_command(label="Edit", command=self.edit_password)
            context_menu.add_command(label="Delete", command=self.delete_password)
            
            # Show menu
            context_menu.tk_popup(event.x_root, event.y_root)
    
    def start_session_timer(self):
        """Start session timeout timer."""
        self.stop_session_timer()
        # Auto-lock after specified minutes of inactivity
        self.session_timer = self.root.after(self.auto_lock_minutes * 60 * 1000, self.auto_lock)
        
        # Reset timer on any activity
        self.root.bind_all("<Key>", self.reset_session_timer)
        self.root.bind_all("<Button-1>", self.reset_session_timer)
    
    def reset_session_timer(self, event=None):
        """Reset session timer on activity."""
        if self.is_authenticated:
            self.start_session_timer()
    
    def stop_session_timer(self):
        """Stop session timer."""
        if self.session_timer:
            self.root.after_cancel(self.session_timer)
            self.session_timer = None
    
    def auto_lock(self):
        """Auto-lock the vault."""
        if self.is_authenticated:
            messagebox.showinfo("Session Timeout", "Session timed out. Vault locked for security.")
            self.lock_vault()
    
    def open_password_generator(self):
        """Open password generator window."""
        PasswordGeneratorDialog(self.root, self.password_generator)
    
    def setup_2fa(self):
        """Setup two-factor authentication."""
        TwoFactorSetupDialog(self.root, self.two_factor)
    
    def import_csv(self):
        """Import passwords from CSV file."""
        if not self.is_authenticated:
            messagebox.showwarning("Not Authenticated", "Please unlock your vault first.")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select CSV file to import",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            migration = CSVMigration(self.db_manager)
            success, message = migration.migrate_csv_file(file_path)
            
            if success:
                messagebox.showinfo("Import Complete", message)
                self.refresh_password_list()
            else:
                messagebox.showerror("Import Failed", message)
    
    def export_backup(self):
        """Export encrypted backup."""
        if not self.is_authenticated:
            messagebox.showwarning("Not Authenticated", "Please unlock your vault first.")
            return
        
        # Get export password
        export_password = simpledialog.askstring("Export Password", 
                                                "Enter password for backup file:", show='*')
        if not export_password:
            return
        
        # Get save location
        file_path = filedialog.asksaveasfilename(
            title="Save backup file",
            defaultextension=".backup",
            filetypes=[("Backup files", "*.backup"), ("All files", "*.*")]
        )
        
        if file_path:
            backup_data = self.db_manager.export_data(export_password)
            if backup_data:
                try:
                    with open(file_path, 'w') as f:
                        f.write(backup_data)
                    messagebox.showinfo("Backup Complete", "Backup saved successfully!")
                except Exception as e:
                    messagebox.showerror("Backup Failed", f"Failed to save backup: {e}")
            else:
                messagebox.showerror("Backup Failed", "Failed to create backup.")
    
    def show_about(self):
        """Show about dialog."""
        messagebox.showinfo("About PyPass", 
                          "PyPass - Secure Password Manager\n\n"
                          "Version 2.0\n"
                          "Features:\n"
                          "• AES-256 encryption\n"
                          "• Password generation\n"
                          "• Two-factor authentication\n"
                          "• Secure database storage\n"
                          "• CSV import/export")
    
    def on_closing(self):
        """Handle application closing."""
        if self.is_authenticated:
            self.db_manager.close()
        self.root.destroy()
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


from .dialogs import NewVaultDialog, PasswordDialog, PasswordGeneratorDialog, TwoFactorSetupDialog