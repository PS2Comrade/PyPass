"""
Dialog windows for PyPass GUI application.
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional, Tuple, Dict, Any
import sys
import os
from PIL import Image, ImageTk
import io

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pypass.core.password_generator import PasswordGenerator, PasswordStrength
from pypass.core.two_factor import TwoFactorAuth
from pypass.database.manager import PasswordEntry


class NewVaultDialog:
    """Dialog for creating a new vault."""
    
    def __init__(self, parent):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Create New Vault")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (300 // 2)
        self.dialog.geometry(f"400x300+{x}+{y}")
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Create New Password Vault", 
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Info
        info_label = ttk.Label(main_frame, 
                              text="Choose a strong master password to protect your vault.\n"
                                   "This password cannot be recovered if forgotten.",
                              justify=tk.CENTER)
        info_label.pack(pady=(0, 20))
        
        # Password fields
        ttk.Label(main_frame, text="Master Password:").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(main_frame, show="*", width=40)
        self.password_entry.pack(pady=(5, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Confirm Password:").pack(anchor=tk.W)
        self.confirm_entry = ttk.Entry(main_frame, show="*", width=40)
        self.confirm_entry.pack(pady=(5, 20), fill=tk.X)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Create Vault", command=self.create).pack(side=tk.RIGHT)
        
        # Bind Enter key
        self.dialog.bind("<Return>", lambda e: self.create())
        self.password_entry.focus()
    
    def create(self):
        """Create vault with entered passwords."""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password.")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")
            return
        
        self.result = (password, confirm)
        self.dialog.destroy()
    
    def cancel(self):
        """Cancel dialog."""
        self.dialog.destroy()


class PasswordDialog:
    """Dialog for adding/editing password entries."""
    
    def __init__(self, parent, title: str, entry: Optional[PasswordEntry] = None):
        self.result = None
        self.entry = entry
        self.generator = PasswordGenerator()
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("500x600")
        self.dialog.resizable(True, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (600 // 2)
        self.dialog.geometry(f"500x600+{x}+{y}")
        
        self.create_widgets()
        self.populate_fields()
        
    def create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Basic tab
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="Basic Info")
        self.create_basic_tab(basic_frame)
        
        # Advanced tab
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="Advanced")
        self.create_advanced_tab(advanced_frame)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Save", command=self.save).pack(side=tk.RIGHT)
    
    def create_basic_tab(self, parent):
        """Create basic information tab."""
        # Name
        ttk.Label(parent, text="Name *:").pack(anchor=tk.W, pady=(10, 0))
        self.name_entry = ttk.Entry(parent, width=60)
        self.name_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Username
        ttk.Label(parent, text="Username/Email *:").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(parent, width=60)
        self.username_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Password with generator
        password_frame = ttk.Frame(parent)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(password_frame, text="Password *:").pack(anchor=tk.W)
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.password_entry = ttk.Entry(password_input_frame, show="*", width=50)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(password_input_frame, text="Show", variable=self.show_password_var,
                       command=self.toggle_password_visibility).pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(password_input_frame, text="Generate", command=self.generate_password).pack(side=tk.RIGHT, padx=(5, 0))\n        \n        # Password strength indicator\n        self.strength_frame = ttk.Frame(password_frame)\n        self.strength_frame.pack(fill=tk.X, pady=(5, 0))\n        \n        self.strength_label = ttk.Label(self.strength_frame, text=\"Password Strength:\")\n        self.strength_label.pack(side=tk.LEFT)\n        \n        self.strength_bar = ttk.Progressbar(self.strength_frame, length=200, mode='determinate')\n        self.strength_bar.pack(side=tk.LEFT, padx=(10, 0))\n        \n        self.strength_text = ttk.Label(self.strength_frame, text=\"\")\n        self.strength_text.pack(side=tk.LEFT, padx=(10, 0))\n        \n        # Bind password change event\n        self.password_entry.bind('<KeyRelease>', self.update_password_strength)\n        \n        # URL\n        ttk.Label(parent, text=\"URL:\").pack(anchor=tk.W)\n        self.url_entry = ttk.Entry(parent, width=60)\n        self.url_entry.pack(fill=tk.X, pady=(5, 10))\n        \n        # Category\n        ttk.Label(parent, text=\"Category:\").pack(anchor=tk.W)\n        self.category_var = tk.StringVar(value=\"General\")\n        self.category_combo = ttk.Combobox(parent, textvariable=self.category_var, width=57)\n        self.category_combo['values'] = ('General', 'Email', 'Social', 'Banking', 'Work', 'Shopping', 'Entertainment')\n        self.category_combo.pack(fill=tk.X, pady=(5, 10))\n    \n    def create_advanced_tab(self, parent):\n        \"\"\"Create advanced options tab.\"\"\"\n        # Notes\n        ttk.Label(parent, text=\"Notes:\").pack(anchor=tk.W, pady=(10, 0))\n        \n        notes_frame = ttk.Frame(parent)\n        notes_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10))\n        \n        self.notes_text = tk.Text(notes_frame, height=10, width=60)\n        notes_scrollbar = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=self.notes_text.yview)\n        self.notes_text.configure(yscrollcommand=notes_scrollbar.set)\n        \n        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)\n        notes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)\n        \n        # Additional info\n        info_frame = ttk.LabelFrame(parent, text=\"Information\")\n        info_frame.pack(fill=tk.X, pady=(10, 0))\n        \n        if self.entry:\n            ttk.Label(info_frame, text=f\"Created: {self.entry.created_at[:19]}\").pack(anchor=tk.W, padx=10, pady=5)\n            ttk.Label(info_frame, text=f\"Modified: {self.entry.updated_at[:19]}\").pack(anchor=tk.W, padx=10, pady=5)\n            if self.entry.accessed_at:\n                ttk.Label(info_frame, text=f\"Last Accessed: {self.entry.accessed_at[:19]}\").pack(anchor=tk.W, padx=10, pady=5)\n    \n    def populate_fields(self):\n        \"\"\"Populate fields if editing existing entry.\"\"\"\n        if self.entry:\n            self.name_entry.insert(0, self.entry.name)\n            self.username_entry.insert(0, self.entry.username)\n            self.password_entry.insert(0, self.entry.password)\n            \n            if self.entry.url:\n                self.url_entry.insert(0, self.entry.url)\n            \n            self.category_var.set(self.entry.category)\n            \n            if self.entry.notes:\n                self.notes_text.insert(tk.END, self.entry.notes)\n            \n            # Update password strength\n            self.update_password_strength()\n        \n        self.name_entry.focus()\n    \n    def toggle_password_visibility(self):\n        \"\"\"Toggle password visibility.\"\"\"\n        if self.show_password_var.get():\n            self.password_entry.configure(show=\"\")\n        else:\n            self.password_entry.configure(show=\"*\")\n    \n    def generate_password(self):\n        \"\"\"Generate a new password.\"\"\"\n        generator_dialog = PasswordGeneratorDialog(self.dialog, self.generator, self.set_generated_password)\n    \n    def set_generated_password(self, password: str):\n        \"\"\"Set generated password in the entry field.\"\"\"\n        self.password_entry.delete(0, tk.END)\n        self.password_entry.insert(0, password)\n        self.update_password_strength()\n    \n    def update_password_strength(self, event=None):\n        \"\"\"Update password strength indicator.\"\"\"\n        password = self.password_entry.get()\n        if not password:\n            self.strength_bar['value'] = 0\n            self.strength_text.configure(text=\"\")\n            return\n        \n        strength, score, criteria = self.generator.analyze_password_strength(password)\n        \n        # Update progress bar (scale score to 0-100)\n        progress = min(100, (score / 10) * 100)\n        self.strength_bar['value'] = progress\n        \n        # Update text and color\n        description = self.generator.get_strength_description(strength)\n        self.strength_text.configure(text=description)\n        \n        # You could also change the color of the progress bar here if needed\n    \n    def save(self):\n        \"\"\"Save the password entry.\"\"\"\n        name = self.name_entry.get().strip()\n        username = self.username_entry.get().strip()\n        password = self.password_entry.get()\n        url = self.url_entry.get().strip()\n        category = self.category_var.get()\n        notes = self.notes_text.get(\"1.0\", tk.END).strip()\n        \n        if not name:\n            messagebox.showerror(\"Error\", \"Name is required.\")\n            return\n        \n        if not username:\n            messagebox.showerror(\"Error\", \"Username is required.\")\n            return\n        \n        if not password:\n            messagebox.showerror(\"Error\", \"Password is required.\")\n            return\n        \n        self.result = {\n            'name': name,\n            'username': username,\n            'password': password,\n            'url': url or None,\n            'category': category,\n            'notes': notes or None\n        }\n        \n        self.dialog.destroy()\n    \n    def cancel(self):\n        \"\"\"Cancel dialog.\"\"\"\n        self.dialog.destroy()\n\n\nclass PasswordGeneratorDialog:\n    \"\"\"Dialog for password generation with advanced options.\"\"\"\n    \n    def __init__(self, parent, generator: PasswordGenerator, callback=None):\n        self.generator = generator\n        self.callback = callback\n        \n        self.dialog = tk.Toplevel(parent)\n        self.dialog.title(\"Password Generator\")\n        self.dialog.geometry(\"450x550\")\n        self.dialog.resizable(False, False)\n        self.dialog.transient(parent)\n        self.dialog.grab_set()\n        \n        # Center dialog\n        self.dialog.update_idletasks()\n        x = (self.dialog.winfo_screenwidth() // 2) - (450 // 2)\n        y = (self.dialog.winfo_screenheight() // 2) - (550 // 2)\n        self.dialog.geometry(f\"450x550+{x}+{y}\")\n        \n        self.create_widgets()\n        self.generate_password()\n    \n    def create_widgets(self):\n        \"\"\"Create dialog widgets.\"\"\"\n        main_frame = ttk.Frame(self.dialog)\n        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)\n        \n        # Generated password display\n        password_frame = ttk.LabelFrame(main_frame, text=\"Generated Password\")\n        password_frame.pack(fill=tk.X, pady=(0, 15))\n        \n        self.password_var = tk.StringVar()\n        password_display_frame = ttk.Frame(password_frame)\n        password_display_frame.pack(fill=tk.X, padx=10, pady=10)\n        \n        self.password_display = ttk.Entry(password_display_frame, textvariable=self.password_var, \n                                         font=(\"Courier\", 12), state=\"readonly\")\n        self.password_display.pack(side=tk.LEFT, fill=tk.X, expand=True)\n        \n        ttk.Button(password_display_frame, text=\"Copy\", command=self.copy_password).pack(side=tk.RIGHT, padx=(5, 0))\n        \n        # Password strength\n        strength_frame = ttk.Frame(password_frame)\n        strength_frame.pack(fill=tk.X, padx=10, pady=(0, 10))\n        \n        ttk.Label(strength_frame, text=\"Strength:\").pack(side=tk.LEFT)\n        \n        self.strength_bar = ttk.Progressbar(strength_frame, length=200, mode='determinate')\n        self.strength_bar.pack(side=tk.LEFT, padx=(10, 0))\n        \n        self.strength_label = ttk.Label(strength_frame, text=\"\")\n        self.strength_label.pack(side=tk.LEFT, padx=(10, 0))\n        \n        # Options\n        options_frame = ttk.LabelFrame(main_frame, text=\"Options\")\n        options_frame.pack(fill=tk.X, pady=(0, 15))\n        \n        # Length\n        length_frame = ttk.Frame(options_frame)\n        length_frame.pack(fill=tk.X, padx=10, pady=10)\n        \n        ttk.Label(length_frame, text=\"Length:\").pack(side=tk.LEFT)\n        \n        self.length_var = tk.IntVar(value=16)\n        self.length_scale = ttk.Scale(length_frame, from_=8, to=64, orient=tk.HORIZONTAL,\n                                     variable=self.length_var, command=self.on_option_change)\n        self.length_scale.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))\n        \n        self.length_label = ttk.Label(length_frame, text=\"16\")\n        self.length_label.pack(side=tk.RIGHT)\n        \n        # Character types\n        chars_frame = ttk.Frame(options_frame)\n        chars_frame.pack(fill=tk.X, padx=10, pady=(0, 10))\n        \n        self.use_lowercase = tk.BooleanVar(value=True)\n        self.use_uppercase = tk.BooleanVar(value=True)\n        self.use_digits = tk.BooleanVar(value=True)\n        self.use_symbols = tk.BooleanVar(value=True)\n        self.exclude_ambiguous = tk.BooleanVar(value=False)\n        \n        ttk.Checkbutton(chars_frame, text=\"Lowercase (a-z)\", variable=self.use_lowercase,\n                       command=self.on_option_change).pack(anchor=tk.W)\n        ttk.Checkbutton(chars_frame, text=\"Uppercase (A-Z)\", variable=self.use_uppercase,\n                       command=self.on_option_change).pack(anchor=tk.W)\n        ttk.Checkbutton(chars_frame, text=\"Digits (0-9)\", variable=self.use_digits,\n                       command=self.on_option_change).pack(anchor=tk.W)\n        ttk.Checkbutton(chars_frame, text=\"Symbols (!@#$...)\", variable=self.use_symbols,\n                       command=self.on_option_change).pack(anchor=tk.W)\n        ttk.Checkbutton(chars_frame, text=\"Exclude ambiguous (0O1lI)\", variable=self.exclude_ambiguous,\n                       command=self.on_option_change).pack(anchor=tk.W)\n        \n        # Memorable password option\n        memorable_frame = ttk.LabelFrame(main_frame, text=\"Alternative\")\n        memorable_frame.pack(fill=tk.X, pady=(0, 15))\n        \n        ttk.Button(memorable_frame, text=\"Generate Memorable Password\", \n                  command=self.generate_memorable).pack(padx=10, pady=10)\n        \n        # Buttons\n        button_frame = ttk.Frame(main_frame)\n        button_frame.pack(fill=tk.X)\n        \n        ttk.Button(button_frame, text=\"Generate New\", command=self.generate_password).pack(side=tk.LEFT)\n        \n        if self.callback:\n            ttk.Button(button_frame, text=\"Use Password\", command=self.use_password).pack(side=tk.RIGHT, padx=(10, 0))\n        \n        ttk.Button(button_frame, text=\"Close\", command=self.close).pack(side=tk.RIGHT)\n    \n    def on_option_change(self, *args):\n        \"\"\"Handle option changes.\"\"\"\n        # Update length label\n        self.length_label.configure(text=str(int(self.length_var.get())))\n        \n        # Auto-generate new password\n        self.generate_password()\n    \n    def generate_password(self):\n        \"\"\"Generate a new password.\"\"\"\n        try:\n            password = self.generator.generate_password(\n                length=int(self.length_var.get()),\n                use_lowercase=self.use_lowercase.get(),\n                use_uppercase=self.use_uppercase.get(),\n                use_digits=self.use_digits.get(),\n                use_symbols=self.use_symbols.get(),\n                exclude_ambiguous=self.exclude_ambiguous.get()\n            )\n            \n            self.password_var.set(password)\n            self.update_strength(password)\n            \n        except ValueError as e:\n            messagebox.showerror(\"Error\", str(e))\n    \n    def generate_memorable(self):\n        \"\"\"Generate a memorable password.\"\"\"\n        password = self.generator.generate_memorable_password()\n        self.password_var.set(password)\n        self.update_strength(password)\n    \n    def update_strength(self, password: str):\n        \"\"\"Update password strength display.\"\"\"\n        strength, score, criteria = self.generator.analyze_password_strength(password)\n        \n        # Update progress bar\n        progress = min(100, (score / 10) * 100)\n        self.strength_bar['value'] = progress\n        \n        # Update label\n        description = self.generator.get_strength_description(strength)\n        self.strength_label.configure(text=description)\n    \n    def copy_password(self):\n        \"\"\"Copy password to clipboard.\"\"\"\n        password = self.password_var.get()\n        if password:\n            self.dialog.clipboard_clear()\n            self.dialog.clipboard_append(password)\n            messagebox.showinfo(\"Copied\", \"Password copied to clipboard!\")\n    \n    def use_password(self):\n        \"\"\"Use the generated password.\"\"\"\n        password = self.password_var.get()\n        if password and self.callback:\n            self.callback(password)\n        self.dialog.destroy()\n    \n    def close(self):\n        \"\"\"Close dialog.\"\"\"\n        self.dialog.destroy()\n\n\nclass TwoFactorSetupDialog:\n    \"\"\"Dialog for setting up two-factor authentication.\"\"\"\n    \n    def __init__(self, parent, two_factor: TwoFactorAuth):\n        self.two_factor = two_factor\n        \n        self.dialog = tk.Toplevel(parent)\n        self.dialog.title(\"Setup Two-Factor Authentication\")\n        self.dialog.geometry(\"500x700\")\n        self.dialog.resizable(False, False)\n        self.dialog.transient(parent)\n        self.dialog.grab_set()\n        \n        # Center dialog\n        self.dialog.update_idletasks()\n        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)\n        y = (self.dialog.winfo_screenheight() // 2) - (700 // 2)\n        self.dialog.geometry(f\"500x700+{x}+{y}\")\n        \n        self.secret = self.two_factor.generate_secret()\n        self.create_widgets()\n    \n    def create_widgets(self):\n        \"\"\"Create dialog widgets.\"\"\"\n        main_frame = ttk.Frame(self.dialog)\n        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)\n        \n        # Title\n        title_label = ttk.Label(main_frame, text=\"Setup Two-Factor Authentication\", \n                               font=(\"Arial\", 14, \"bold\"))\n        title_label.pack(pady=(0, 20))\n        \n        # Instructions\n        instructions = (\n            \"1. Install an authenticator app (Google Authenticator, Authy, etc.)\\n\"\n            \"2. Scan the QR code below or enter the secret manually\\n\"\n            \"3. Enter the 6-digit code from your app to verify setup\"\n        )\n        \n        ttk.Label(main_frame, text=instructions, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 20))\n        \n        # QR Code\n        qr_frame = ttk.LabelFrame(main_frame, text=\"QR Code\")\n        qr_frame.pack(fill=tk.X, pady=(0, 20))\n        \n        try:\n            qr_data = self.two_factor.generate_qr_code(self.secret, \"PyPass User\")\n            \n            # Convert to Tkinter format\n            qr_image = Image.open(io.BytesIO(qr_data))\n            qr_image = qr_image.resize((200, 200), Image.Resampling.LANCZOS)\n            self.qr_photo = ImageTk.PhotoImage(qr_image)\n            \n            qr_label = ttk.Label(qr_frame, image=self.qr_photo)\n            qr_label.pack(padx=10, pady=10)\n            \n        except Exception as e:\n            ttk.Label(qr_frame, text=f\"Error generating QR code: {e}\").pack(padx=10, pady=10)\n        \n        # Manual entry\n        secret_frame = ttk.LabelFrame(main_frame, text=\"Manual Entry\")\n        secret_frame.pack(fill=tk.X, pady=(0, 20))\n        \n        ttk.Label(secret_frame, text=\"Secret Key:\").pack(anchor=tk.W, padx=10, pady=(10, 5))\n        \n        secret_display_frame = ttk.Frame(secret_frame)\n        secret_display_frame.pack(fill=tk.X, padx=10, pady=(0, 10))\n        \n        self.secret_var = tk.StringVar(value=self.two_factor.format_secret_for_display(self.secret))\n        secret_entry = ttk.Entry(secret_display_frame, textvariable=self.secret_var, \n                                state=\"readonly\", font=(\"Courier\", 10))\n        secret_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)\n        \n        ttk.Button(secret_display_frame, text=\"Copy\", command=self.copy_secret).pack(side=tk.RIGHT, padx=(5, 0))\n        \n        # Verification\n        verify_frame = ttk.LabelFrame(main_frame, text=\"Verification\")\n        verify_frame.pack(fill=tk.X, pady=(0, 20))\n        \n        ttk.Label(verify_frame, text=\"Enter 6-digit code from authenticator app:\").pack(anchor=tk.W, padx=10, pady=(10, 5))\n        \n        verify_input_frame = ttk.Frame(verify_frame)\n        verify_input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))\n        \n        self.code_entry = ttk.Entry(verify_input_frame, width=10, font=(\"Courier\", 14))\n        self.code_entry.pack(side=tk.LEFT)\n        \n        ttk.Button(verify_input_frame, text=\"Verify\", command=self.verify_code).pack(side=tk.LEFT, padx=(10, 0))\n        \n        # Current code (for testing)\n        current_code = self.two_factor.get_current_token(self.secret)\n        ttk.Label(verify_frame, text=f\"Current code (for testing): {current_code}\", \n                 font=(\"Courier\", 10)).pack(anchor=tk.W, padx=10, pady=(10, 10))\n        \n        # Backup codes\n        backup_frame = ttk.LabelFrame(main_frame, text=\"Backup Codes\")\n        backup_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))\n        \n        ttk.Label(backup_frame, text=\"Save these backup codes in a safe place:\").pack(anchor=tk.W, padx=10, pady=(10, 5))\n        \n        backup_codes = self.two_factor.get_backup_codes()\n        codes_text = \"\\n\".join(f\"{i+1:2d}. {code}\" for i, code in enumerate(backup_codes))\n        \n        codes_display = tk.Text(backup_frame, height=6, width=40, font=(\"Courier\", 10))\n        codes_display.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)\n        codes_display.insert(tk.END, codes_text)\n        codes_display.configure(state=\"disabled\")\n        \n        # Buttons\n        button_frame = ttk.Frame(main_frame)\n        button_frame.pack(fill=tk.X)\n        \n        ttk.Button(button_frame, text=\"Cancel\", command=self.cancel).pack(side=tk.RIGHT, padx=(10, 0))\n        ttk.Button(button_frame, text=\"Complete Setup\", command=self.complete_setup).pack(side=tk.RIGHT)\n        \n        self.code_entry.focus()\n    \n    def copy_secret(self):\n        \"\"\"Copy secret to clipboard.\"\"\"\n        self.dialog.clipboard_clear()\n        self.dialog.clipboard_append(self.secret)\n        messagebox.showinfo(\"Copied\", \"Secret copied to clipboard!\")\n    \n    def verify_code(self):\n        \"\"\"Verify the entered code.\"\"\"\n        code = self.code_entry.get().strip()\n        \n        if len(code) != 6 or not code.isdigit():\n            messagebox.showerror(\"Error\", \"Please enter a 6-digit code.\")\n            return\n        \n        if self.two_factor.verify_token(self.secret, code):\n            messagebox.showinfo(\"Success\", \"Code verified successfully!\")\n        else:\n            messagebox.showerror(\"Error\", \"Invalid code. Please try again.\")\n    \n    def complete_setup(self):\n        \"\"\"Complete 2FA setup.\"\"\"\n        code = self.code_entry.get().strip()\n        \n        if not code or len(code) != 6:\n            messagebox.showerror(\"Error\", \"Please verify your setup with a 6-digit code first.\")\n            return\n        \n        if not self.two_factor.verify_token(self.secret, code):\n            messagebox.showerror(\"Error\", \"Please verify your setup with a valid code first.\")\n            return\n        \n        # In a real implementation, you would save the secret securely\n        messagebox.showinfo(\"Setup Complete\", \n                          \"Two-factor authentication has been set up successfully!\\n\"\n                          \"Make sure to save your backup codes in a secure location.\")\n        \n        self.dialog.destroy()\n    \n    def cancel(self):\n        \"\"\"Cancel setup.\"\"\"\n        self.dialog.destroy()