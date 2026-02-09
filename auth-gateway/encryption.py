"""
Fernet Encryption Service
Handles encryption/decryption of OAuth tokens with key rotation support.
"""
import base64
import hashlib
import logging
from typing import Optional, List
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class EncryptionService:
    """
    Encryption service using Fernet (AES-128-CBC + HMAC-SHA256).
    Supports key rotation for zero-downtime key changes.
    """
    
    def __init__(
        self,
        primary_key: str,
        salt: Optional[str] = None,
        rotation_keys: Optional[List[str]] = None
    ):
        """
        Initialize encryption service.
        
        Args:
            primary_key: Main encryption key (32+ chars)
            salt: Optional salt for key derivation
            rotation_keys: Old keys for decryption during rotation
        """
        self.primary_fernet = self._create_fernet(primary_key, salt)
        
        # Create Fernet instances for rotation keys (decrypt only)
        self.rotation_fernets: List[Fernet] = []
        if rotation_keys:
            for key in rotation_keys:
                try:
                    self.rotation_fernets.append(self._create_fernet(key, salt))
                except Exception as e:
                    logger.warning(f"Invalid rotation key skipped: {e}")
    
    def _create_fernet(self, key: str, salt: Optional[str] = None) -> Fernet:
        """
        Create Fernet instance from key string.
        Derives a proper 32-byte key using SHA-256.
        """
        # Combine key with optional salt
        key_material = key
        if salt:
            key_material = f"{key}{salt}"
        
        # Derive 32-byte key using SHA-256, then base64 encode for Fernet
        derived_key = hashlib.sha256(key_material.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(derived_key)
        
        return Fernet(fernet_key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty string")
        
        encrypted = self.primary_fernet.encrypt(plaintext.encode('utf-8'))
        return encrypted.decode('utf-8')
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext string.
        Tries primary key first, then rotation keys.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            InvalidToken: If decryption fails with all keys
        """
        if not ciphertext:
            raise ValueError("Cannot decrypt empty string")
        
        ciphertext_bytes = ciphertext.encode('utf-8')
        
        # Try primary key first
        try:
            decrypted = self.primary_fernet.decrypt(ciphertext_bytes)
            return decrypted.decode('utf-8')
        except InvalidToken:
            pass
        
        # Try rotation keys
        for fernet in self.rotation_fernets:
            try:
                decrypted = fernet.decrypt(ciphertext_bytes)
                logger.info("Decrypted with rotation key - consider re-encrypting")
                return decrypted.decode('utf-8')
            except InvalidToken:
                continue
        
        # All keys failed
        raise InvalidToken("Failed to decrypt with any available key")
    
    def needs_reencryption(self, ciphertext: str) -> bool:
        """
        Check if ciphertext was encrypted with a rotation key
        and needs re-encryption with the primary key.
        """
        try:
            self.primary_fernet.decrypt(ciphertext.encode('utf-8'))
            return False  # Primary key works, no re-encryption needed
        except InvalidToken:
            # Try rotation keys
            for fernet in self.rotation_fernets:
                try:
                    fernet.decrypt(ciphertext.encode('utf-8'))
                    return True  # Rotation key works, needs re-encryption
                except InvalidToken:
                    continue
            raise InvalidToken("Cannot decrypt with any key")
    
    def reencrypt(self, ciphertext: str) -> str:
        """
        Decrypt with any available key and re-encrypt with primary key.
        Used during key rotation.
        """
        plaintext = self.decrypt(ciphertext)
        return self.encrypt(plaintext)


# Factory function
def create_encryption_service(
    primary_key: str,
    salt: Optional[str] = None,
    rotation_keys: Optional[List[str]] = None
) -> EncryptionService:
    """Create and return encryption service instance."""
    return EncryptionService(primary_key, salt, rotation_keys)
