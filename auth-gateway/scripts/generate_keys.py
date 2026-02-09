#!/usr/bin/env python3
"""
Generate Encryption and API Keys
Creates secure keys for Auth Gateway configuration.
"""
import secrets
import base64
import hashlib
import argparse


def generate_encryption_key() -> str:
    """Generate a 32-byte encryption key."""
    # Generate 32 random bytes
    key_bytes = secrets.token_bytes(32)
    # Return as URL-safe base64 string
    return base64.urlsafe_b64encode(key_bytes).decode('utf-8')


def generate_api_key(length: int = 64) -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(length)


def generate_salt() -> str:
    """Generate a salt for key derivation."""
    return secrets.token_hex(16)


def main():
    parser = argparse.ArgumentParser(description="Generate Auth Gateway keys")
    parser.add_argument('--api-key', action='store_true', help='Generate API key only')
    parser.add_argument('--encryption-key', action='store_true', help='Generate encryption key only')
    parser.add_argument('--salt', action='store_true', help='Generate salt only')
    parser.add_argument('--rotate', action='store_true', help='Show rotation instructions')
    parser.add_argument('--all', action='store_true', help='Generate all keys (default)')
    
    args = parser.parse_args()
    
    # Default to --all if no specific flag
    if not (args.api_key or args.encryption_key or args.salt or args.rotate):
        args.all = True
    
    if args.rotate:
        print("\n🔄 Key Rotation Instructions")
        print("=" * 50)
        print("1. Generate new encryption key:")
        new_key = generate_encryption_key()
        print(f"   AUTH_GATEWAY_ENCRYPTION_KEY={new_key}")
        print("\n2. Move current key to rotation keys:")
        print("   AUTH_GATEWAY_ROTATION_KEYS=<your-current-key>")
        print("\n3. Restart Auth Gateway")
        print("4. Run reencrypt_tokens.py to migrate tokens")
        print("5. After 48 hours, remove AUTH_GATEWAY_ROTATION_KEYS")
        return
    
    print("\n🔐 Auth Gateway Key Generator")
    print("=" * 50)
    
    if args.all or args.encryption_key:
        key = generate_encryption_key()
        print(f"\n📦 Encryption Key:")
        print(f"   AUTH_GATEWAY_ENCRYPTION_KEY={key}")
    
    if args.all or args.salt:
        salt = generate_salt()
        print(f"\n🧂 Encryption Salt (optional):")
        print(f"   AUTH_GATEWAY_ENCRYPTION_KEY_SALT={salt}")
    
    if args.all or args.api_key:
        api_key = generate_api_key()
        print(f"\n🔑 API Key:")
        print(f"   AUTH_GATEWAY_API_KEY={api_key}")
    
    print("\n" + "=" * 50)
    print("⚠️  Store these securely! Never commit to Git.")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
