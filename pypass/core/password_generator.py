"""
Password generator with customizable options and strength analysis.
"""
import secrets
import string
import re
from typing import Dict, Tuple
from enum import Enum


class PasswordStrength(Enum):
    """Password strength levels."""
    VERY_WEAK = 1
    WEAK = 2
    FAIR = 3
    GOOD = 4
    STRONG = 5


class PasswordGenerator:
    """Generate secure passwords with customizable options."""
    
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "0O1lI"  # Characters that can be confused
        
    def generate_password(self, 
                         length: int = 16,
                         use_lowercase: bool = True,
                         use_uppercase: bool = True,
                         use_digits: bool = True,
                         use_symbols: bool = True,
                         exclude_ambiguous: bool = False,
                         ensure_all_types: bool = True) -> str:
        """
        Generate a password with specified criteria.
        
        Args:
            length: Password length
            use_lowercase: Include lowercase letters
            use_uppercase: Include uppercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters
            ensure_all_types: Ensure at least one character from each enabled type
        """
        if length < 1:
            raise ValueError("Password length must be at least 1")
        
        # Build character set
        charset = ""
        required_chars = []
        
        if use_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if ensure_all_types:
                required_chars.append(secrets.choice(chars))
        
        if use_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if ensure_all_types:
                required_chars.append(secrets.choice(chars))
        
        if use_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            if ensure_all_types:
                required_chars.append(secrets.choice(chars))
        
        if use_symbols:
            charset += self.symbols
            if ensure_all_types:
                required_chars.append(secrets.choice(self.symbols))
        
        if not charset:
            raise ValueError("At least one character type must be enabled")
        
        # Calculate remaining length after required characters
        remaining_length = length - len(required_chars)
        if remaining_length < 0:
            # If required chars exceed length, just use required chars
            password_chars = required_chars[:length]
        else:
            # Generate remaining characters
            random_chars = [secrets.choice(charset) for _ in range(remaining_length)]
            password_chars = required_chars + random_chars
        
        # Shuffle the password characters
        password_list = list(password_chars)
        for i in range(len(password_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_list[i], password_list[j] = password_list[j], password_list[i]
        
        return ''.join(password_list)
    
    def generate_memorable_password(self, num_words: int = 4, separator: str = "-") -> str:
        """
        Generate a memorable password using random words.
        This is a simple implementation - in practice, you'd want a word list.
        """
        # Simple word list for demonstration
        words = [
            "apple", "banana", "cherry", "dragon", "elephant", "falcon", "guitar",
            "hammer", "island", "jungle", "keyboard", "lightning", "mountain",
            "ocean", "piano", "quantum", "rainbow", "sunset", "thunder", "universe",
            "volcano", "whisper", "xenon", "yellow", "zebra", "bridge", "castle",
            "forest", "galaxy", "harbor", "library", "market", "network", "palace",
            "river", "silver", "tower", "victory", "winter", "crystal", "diamond"
        ]
        
        selected_words = [secrets.choice(words) for _ in range(num_words)]
        
        # Capitalize random words
        for i in range(len(selected_words)):
            if secrets.randbelow(2):  # 50% chance to capitalize
                selected_words[i] = selected_words[i].capitalize()
        
        # Add random numbers
        if secrets.randbelow(2):  # 50% chance to add numbers
            selected_words.append(str(secrets.randbelow(9999)).zfill(2))
        
        return separator.join(selected_words)
    
    def analyze_password_strength(self, password: str) -> Tuple[PasswordStrength, int, Dict[str, bool]]:
        """
        Analyze password strength and return score with criteria details.
        
        Returns:
            (strength_level, score, criteria_dict)
        """
        score = 0
        criteria = {
            "length_8_plus": len(password) >= 8,
            "length_12_plus": len(password) >= 12,
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_digits": bool(re.search(r'\d', password)),
            "has_symbols": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
            "no_repeating": not bool(re.search(r'(.)\1{2,}', password)),  # No 3+ repeating chars
            "no_common_patterns": not self._has_common_patterns(password),
        }
        
        # Calculate score
        if criteria["length_8_plus"]:
            score += 1
        if criteria["length_12_plus"]:
            score += 1
        if criteria["has_lowercase"]:
            score += 1
        if criteria["has_uppercase"]:
            score += 1
        if criteria["has_digits"]:
            score += 1
        if criteria["has_symbols"]:
            score += 1
        if criteria["no_repeating"]:
            score += 1
        if criteria["no_common_patterns"]:
            score += 1
        
        # Additional length bonus
        if len(password) >= 16:
            score += 1
        if len(password) >= 20:
            score += 1
        
        # Determine strength level
        if score <= 2:
            strength = PasswordStrength.VERY_WEAK
        elif score <= 4:
            strength = PasswordStrength.WEAK
        elif score <= 6:
            strength = PasswordStrength.FAIR
        elif score <= 8:
            strength = PasswordStrength.GOOD
        else:
            strength = PasswordStrength.STRONG
        
        return strength, score, criteria
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common weak patterns."""
        password_lower = password.lower()
        
        # Common patterns to avoid
        patterns = [
            "123", "abc", "qwerty", "password", "admin", "user",
            "000", "111", "222", "333", "444", "555", "666", "777", "888", "999"
        ]
        
        return any(pattern in password_lower for pattern in patterns)
    
    def get_strength_description(self, strength: PasswordStrength) -> str:
        """Get human-readable strength description."""
        descriptions = {
            PasswordStrength.VERY_WEAK: "Very Weak - Easily cracked",
            PasswordStrength.WEAK: "Weak - Could be cracked",
            PasswordStrength.FAIR: "Fair - Moderate security",
            PasswordStrength.GOOD: "Good - Secure for most uses",
            PasswordStrength.STRONG: "Strong - Excellent security"
        }
        return descriptions[strength]
    
    def get_strength_color(self, strength: PasswordStrength) -> str:
        """Get color code for strength indicator."""
        colors = {
            PasswordStrength.VERY_WEAK: "#FF0000",  # Red
            PasswordStrength.WEAK: "#FF6600",       # Orange
            PasswordStrength.FAIR: "#FFCC00",       # Yellow
            PasswordStrength.GOOD: "#66CC00",       # Light Green
            PasswordStrength.STRONG: "#00CC00"      # Green
        }
        return colors[strength]