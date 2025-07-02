# PyPass 2.0 - Secure Password Manager

**🔐 A complete transformation from basic CLI to enterprise-grade password manager**

PyPass has been completely revamped from a simple 30-line script into a secure, modern password manager with military-grade encryption and professional features.

## 🚀 New Features

### 🔐 Security Enhancements
- **AES-256 Encryption**: Military-grade encryption protects all your data
- **PBKDF2 Key Derivation**: Secure master password with 100,000 iterations
- **Encrypted SQLite Database**: No more plain text storage
- **Secure Memory Handling**: Minimizes sensitive data exposure
- **Master Password Protection**: Your vault is locked behind a strong master password

### 🎨 Modern Interfaces
- **GUI Application**: Professional Tkinter-based interface (`python3 main.py`)
- **CLI Application**: Full-featured command-line interface (`python3 pypass_cli.py`)
- **Dark/Light Themes**: Modern UI with theme switching (GUI)
- **Search & Filter**: Easy password management and organization
- **Password Strength Indicator**: Visual feedback for password security

### 🛡️ Advanced Security
- **Two-Factor Authentication (2FA)**: TOTP support with QR code generation
- **Password Generator**: Create strong, customizable passwords
- **Session Management**: Auto-lock with configurable timeout
- **Clipboard Security**: Auto-clearing sensitive data after 30 seconds
- **Audit Trail**: Track password changes and access (database level)

### 📊 Enhanced Features
- **Category Organization**: Group passwords by type/service
- **Backup & Restore**: Encrypted data backup functionality
- **CSV Import/Export**: Seamless migration from other password managers
- **Password Strength Analysis**: Detailed security scoring
- **Memorable Passwords**: Human-friendly password generation option

## 🚀 Quick Start

### GUI Version (Recommended)
```bash
# Install dependencies
pip install -r requirements.txt

# Start the GUI application
python3 main.py
```

### CLI Version (Headless/Server environments)
```bash
# Start the CLI application
python3 pypass_cli.py
```

### Legacy Version (Deprecated - Insecure)
```bash
# The old insecure version (with migration warnings)
python3 src/app.py
```

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/PS2Comrade/PyPass.git
   cd PyPass
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run PyPass:**
   ```bash
   python3 main.py        # GUI version
   python3 pypass_cli.py  # CLI version
   ```

## 🔄 Migration from Legacy Version

If you have existing data in the old CSV format, PyPass 2.0 will automatically detect it and offer to migrate your passwords to the new encrypted database. Your original data will be backed up safely.

## 🔧 Requirements

- Python 3.7+
- cryptography>=41.0.0
- pyotp>=2.8.0
- qrcode[pil]>=7.4.0
- Pillow>=10.0.0
- tkinter (usually included with Python)

## 🛡️ Security Features

### Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: Unique cryptographically secure random salt per encryption
- **Authentication**: Built-in authentication tag prevents tampering

### Password Security
- **Strength Analysis**: 10-point scoring system with detailed criteria
- **Pattern Detection**: Identifies and warns about common weak patterns
- **Character Sets**: Full Unicode support with customizable character sets
- **Length Options**: 8-64 character passwords with smart defaults

### Data Protection
- **Database Encryption**: Entire SQLite database is encrypted
- **Memory Security**: Secure string handling with automatic clearing
- **Session Security**: Configurable auto-lock with timeout
- **Clipboard Security**: Automatic clipboard clearing after 30 seconds

## 📱 Two-Factor Authentication

PyPass 2.0 includes full TOTP (Time-based One-Time Password) support:

- **QR Code Generation**: Easy setup with authenticator apps
- **Backup Codes**: Recovery codes for account access
- **Standard Compliance**: Works with Google Authenticator, Authy, etc.
- **Manual Entry**: Alternative setup for environments without QR scanning

## 🔄 Backup & Recovery

- **Encrypted Backups**: Export your vault with password protection
- **CSV Export**: Compatible with other password managers
- **Legacy Import**: Supports various CSV formats
- **Incremental Backups**: Regular backup reminders and automation

## 🎨 User Interface

### GUI Features
- **Modern Design**: Clean, professional interface
- **Theme Support**: Light and dark modes
- **Responsive Layout**: Adapts to different screen sizes
- **Context Menus**: Right-click functionality
- **Keyboard Shortcuts**: Efficient navigation
- **Search & Filter**: Real-time password filtering

### CLI Features
- **Full Functionality**: Complete password management
- **Secure Input**: Hidden password entry
- **Color Output**: Enhanced readability
- **Batch Operations**: Efficient for scripting
- **Cross-Platform**: Works on Windows, macOS, Linux

## 🔍 Password Management

### Organization
- **Categories**: Group passwords by purpose (Email, Banking, Social, etc.)
- **Search**: Find passwords instantly by name, username, URL, or category
- **Sorting**: Multiple sort options with reverse ordering
- **Filtering**: Quick category-based filtering

### Password Operations
- **Add**: Create new password entries with full metadata
- **Edit**: Update existing passwords with change tracking
- **Delete**: Secure deletion with confirmation prompts
- **Copy**: One-click copying with auto-clear security
- **Generate**: On-demand password generation with customization

## 🛠️ Development

PyPass 2.0 is built with a modular architecture:

```
pypass/
├── core/           # Security, encryption, password generation
├── database/       # Encrypted database management
├── gui/           # Tkinter interface components
└── utils/         # Migration and utility functions
```

### Key Components
- **SecurityManager**: Handles all cryptographic operations
- **DatabaseManager**: Manages encrypted SQLite operations
- **PasswordGenerator**: Advanced password generation and analysis
- **TwoFactorAuth**: TOTP implementation with QR codes

## 📈 Performance

- **Fast Startup**: Optimized initialization and loading
- **Efficient Search**: Indexed database operations
- **Memory Efficient**: Minimal memory footprint
- **Responsive UI**: Non-blocking operations with threading

## 🔒 Privacy

- **No Telemetry**: No data collection or tracking
- **Local Storage**: All data stays on your device
- **Open Source**: Full transparency and auditability
- **No Network**: Works completely offline

## 🧪 Testing

```bash
# Run core functionality tests
python3 test_core.py

# Test CLI functionality
python3 pypass_cli.py

# Test GUI functionality
python3 main.py
```

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

If you encounter any issues or have questions, please open an issue on GitHub.

---

**⚠️ Security Notice**: Always keep your master password secure and create regular backups. PyPass 2.0 uses industry-standard encryption, but the security of your data ultimately depends on the strength of your master password.
