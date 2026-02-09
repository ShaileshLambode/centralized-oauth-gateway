#!/usr/bin/env python3
"""
Initialize Database
Creates database tables for Auth Gateway.
"""
import asyncio
import argparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def init_database():
    """Initialize database tables."""
    from database import engine, Base
    from models import OAuthCredential, OAuthSession
    
    print("🗄️  Initializing Auth Gateway Database")
    print("=" * 50)
    
    try:
        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("✓ Tables created successfully")
        print("  - oauth_credentials")
        print("  - oauth_sessions")
        
        print("\n✅ Database initialization complete!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Initialize Auth Gateway database")
    args = parser.parse_args()
    
    asyncio.run(init_database())


if __name__ == "__main__":
    main()
