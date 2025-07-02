"""
Two-Factor Authentication (2FA) implementation with TOTP support.
"""
import pyotp
import qrcode
import io
import base64
from typing import Optional, Tuple
from PIL import Image


class TwoFactorAuth:
    """Handles TOTP-based two-factor authentication."""
    
    def __init__(self):
        self.issuer_name = "PyPass"
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
    
    def generate_qr_code(self, secret: str, username: str) -> bytes:
        """
        Generate QR code for TOTP setup.
        Returns PNG image data as bytes.
        """
        # Create TOTP instance
        totp = pyotp.TOTP(secret)
        
        # Generate provisioning URI
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer.getvalue()
    
    def verify_token(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify a TOTP token.
        
        Args:
            secret: Base32-encoded secret
            token: 6-digit TOTP token
            window: Time window tolerance (default 1 = 30 seconds before/after)
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception:
            return False
    
    def get_current_token(self, secret: str) -> str:
        """Get the current TOTP token for testing purposes."""
        totp = pyotp.TOTP(secret)
        return totp.now()
    
    def get_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for 2FA recovery."""
        import secrets
        backup_codes = []
        
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') 
                          for _ in range(8))
            backup_codes.append(code)
        
        return backup_codes
    
    def format_secret_for_display(self, secret: str) -> str:
        """Format secret for manual entry (groups of 4 characters)."""
        # Group into sets of 4 characters for easier reading
        formatted = ' '.join(secret[i:i+4] for i in range(0, len(secret), 4))
        return formatted