#!/usr/bin/env python3
"""
Re-encrypt Tokens
Migrates tokens from old encryption key to new key during rotation.
"""
import asyncio
import argparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def reencrypt_tokens(dry_run: bool = False):
    """Re-encrypt all tokens with new primary key."""
    from database import async_session_maker, engine
    from models import OAuthCredential
    from config import settings
    from encryption import create_encryption_service
    from sqlalchemy import select
    
    print("🔄 Token Re-encryption Utility")
    print("=" * 50)
    
    if dry_run:
        print("🔍 DRY RUN MODE - No changes will be made\n")
    
    enc = create_encryption_service(
        settings.AUTH_GATEWAY_ENCRYPTION_KEY,
        settings.AUTH_GATEWAY_ENCRYPTION_KEY_SALT,
        settings.rotation_keys_list
    )
    
    stats = {
        "total": 0,
        "needs_reencrypt": 0,
        "reencrypted": 0,
        "errors": 0
    }
    
    try:
        async with async_session_maker() as session:
            # Get all credentials
            result = await session.execute(select(OAuthCredential))
            credentials = result.scalars().all()
            stats["total"] = len(credentials)
            
            print(f"Found {stats['total']} credentials to check\n")
            
            for cred in credentials:
                try:
                    # Check access token
                    if enc.needs_reencryption(cred.access_token):
                        stats["needs_reencrypt"] += 1
                        print(f"→ {cred.profile_id} ({cred.provider_id}): needs re-encryption")
                        
                        if not dry_run:
                            # Re-encrypt
                            cred.access_token = enc.reencrypt(cred.access_token)
                            if cred.refresh_token:
                                cred.refresh_token = enc.reencrypt(cred.refresh_token)
                            stats["reencrypted"] += 1
                            print(f"  ✓ Re-encrypted")
                    else:
                        print(f"✓ {cred.profile_id} ({cred.provider_id}): OK")
                        
                except Exception as e:
                    stats["errors"] += 1
                    print(f"✗ {cred.profile_id} ({cred.provider_id}): Error - {e}")
            
            if not dry_run and stats["reencrypted"] > 0:
                await session.commit()
        
        print("\n" + "=" * 50)
        print("📊 Summary:")
        print(f"   Total credentials: {stats['total']}")
        print(f"   Needed re-encryption: {stats['needs_reencrypt']}")
        if not dry_run:
            print(f"   Successfully re-encrypted: {stats['reencrypted']}")
        print(f"   Errors: {stats['errors']}")
        
        if stats["errors"] == 0 and (dry_run or stats["needs_reencrypt"] == 0):
            print("\n✅ All tokens are encrypted with primary key!")
        elif not dry_run and stats["reencrypted"] == stats["needs_reencrypt"]:
            print("\n✅ Re-encryption complete! You can now remove rotation keys.")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Re-encrypt tokens with new key")
    parser.add_argument('--dry-run', action='store_true', help='Check without making changes')
    args = parser.parse_args()
    
    asyncio.run(reencrypt_tokens(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
