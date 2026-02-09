"""
Health Check Routes
Simple health and status endpoints.
"""
from fastapi import APIRouter, Depends
from datetime import datetime, timezone

from schemas import HealthResponse
from database import check_db_connection
from dependencies import get_encryption_service

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    Returns status of database and encryption services.
    """
    # Check database
    db_status = "connected" if await check_db_connection() else "disconnected"
    
    # Check encryption
    try:
        enc = get_encryption_service()
        # Quick test
        test_data = "health_check_test"
        encrypted = enc.encrypt(test_data)
        decrypted = enc.decrypt(encrypted)
        enc_status = "operational" if decrypted == test_data else "error"
    except Exception:
        enc_status = "error"
    
    return HealthResponse(
        status="healthy" if db_status == "connected" and enc_status == "operational" else "degraded",
        database=db_status,
        encryption=enc_status,
        version="1.0.0",
        timestamp=datetime.now(timezone.utc)
    )
