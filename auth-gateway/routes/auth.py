"""
OAuth Authentication Routes
All /auth/* endpoints for OAuth flow management.
"""
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import httpx

from config import settings
from models import OAuthCredential, OAuthSession
from schemas import (
    AuthInitRequest, AuthInitResponse,
    AuthStatusResponse,
    TokenRequest, TokenResponse, TokenErrorResponse,
    ProvidersListResponse, ProviderInfo,
    RevokeRequest, RevokeResponse,
    ErrorResponse
)
from dependencies import verify_api_key, get_db_session, get_encryption_service
from encryption import EncryptionService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ============================================
# Google OAuth Configuration
# ============================================

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/analytics.readonly",
    "https://www.googleapis.com/auth/google-ads"
]


# ============================================
# POST /auth/init
# ============================================

@router.post(
    "/init",
    response_model=AuthInitResponse,
    summary="Initialize OAuth flow",
    description="Start OAuth authentication flow. Returns auth URL for user to visit."
)
async def init_oauth(
    request: AuthInitRequest,
    db: AsyncSession = Depends(get_db_session),
    enc: EncryptionService = Depends(get_encryption_service),
    api_key: str = Depends(verify_api_key)
):
    """
    Initialize OAuth flow.
    
    1. Generate unique state token (CSRF protection)
    2. Create pending session in database
    3. Return authorization URL for user
    """
    logger.info(f"Initializing OAuth for {request.user_email} with provider {request.provider}")
    
    # Validate provider
    if request.provider != "google":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {request.provider}. Currently only 'google' is supported."
        )
    
    # Generate secure state token
    state = secrets.token_urlsafe(32)
    
    # Calculate expiry
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.SESSION_EXPIRY_MINUTES)
    
    # Create session record
    session = OAuthSession(
        profile_id=request.user_email,
        provider_id=request.provider,
        state=state,
        status="pending",
        expires_at=expires_at
    )
    db.add(session)
    await db.flush()  # Get the session ID
    
    # Determine scopes
    scopes = request.scopes or GOOGLE_DEFAULT_SCOPES
    scope_string = " ".join(scopes)
    
    # Build authorization URL
    auth_url = (
        f"{GOOGLE_AUTH_URL}"
        f"?client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={scope_string}"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&state={state}"
    )
    
    logger.info(f"Created OAuth session {session.id} for {request.user_email}")
    
    return AuthInitResponse(
        auth_url=auth_url,
        session_id=session.id,
        expires_at=expires_at
    )


# ============================================
# GET /auth/callback/{provider}
# ============================================

@router.get(
    "/callback/{provider}",
    response_class=HTMLResponse,
    summary="OAuth callback handler",
    description="Handles redirect from OAuth provider after user consent."
)
async def oauth_callback(
    provider: str,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session),
    enc: EncryptionService = Depends(get_encryption_service)
):
    """
    Handle OAuth provider callback.
    
    1. Validate state token
    2. Exchange code for tokens
    3. Encrypt and store tokens
    4. Update session status
    """
    logger.info(f"OAuth callback for {provider}, state={state}, error={error}")
    
    # Handle OAuth error
    if error:
        logger.error(f"OAuth error: {error}")
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head><title>Authentication Failed</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc2626;">✗ Authentication Failed</h1>
                <p>OAuth Error: <b>{error}</b></p>
                <p>Please close this window and try again.</p>
            </body>
            </html>
            """,
            status_code=400
        )
    
    # Validate required params
    if not code or not state:
        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>Invalid Request</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc2626;">✗ Invalid Request</h1>
                <p>Missing authorization code or state parameter.</p>
            </body>
            </html>
            """,
            status_code=400
        )
    
    # Find session by state
    result = await db.execute(
        select(OAuthSession).where(
            and_(
                OAuthSession.state == state,
                OAuthSession.status == "pending"
            )
        )
    )
    session = result.scalar_one_or_none()
    
    if not session:
        logger.error(f"Session not found for state: {state}")
        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>Session Not Found</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc2626;">✗ Session Not Found</h1>
                <p>OAuth session expired or already used.</p>
                <p>Please restart authentication.</p>
            </body>
            </html>
            """,
            status_code=404
        )
    
    # Check expiry
    if session.expires_at < datetime.now(timezone.utc):
        session.status = "failed"
        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>Session Expired</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc2626;">✗ Session Expired</h1>
                <p>OAuth session has expired. Please restart authentication.</p>
            </body>
            </html>
            """,
            status_code=410
        )
    
    try:
        # Exchange code for tokens
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI
                }
            )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            session.status = "failed"
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <head><title>Token Exchange Failed</title></head>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h1 style="color: #dc2626;">✗ Token Exchange Failed</h1>
                    <p>Failed to exchange authorization code for tokens.</p>
                    <p>Please try again.</p>
                </body>
                </html>
                """,
                status_code=500
            )
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        
        # Calculate token expiry
        token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        
        # Encrypt tokens
        encrypted_access = enc.encrypt(access_token)
        encrypted_refresh = enc.encrypt(refresh_token) if refresh_token else None
        
        # Check for existing credential
        result = await db.execute(
            select(OAuthCredential).where(
                and_(
                    OAuthCredential.profile_id == session.profile_id,
                    OAuthCredential.provider_id == session.provider_id
                )
            )
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            # Update existing credential
            existing.access_token = encrypted_access
            if encrypted_refresh:
                existing.refresh_token = encrypted_refresh
            existing.token_expiry = token_expiry
        else:
            # Create new credential
            credential = OAuthCredential(
                profile_id=session.profile_id,
                provider_id=session.provider_id,
                access_token=encrypted_access,
                refresh_token=encrypted_refresh,
                token_expiry=token_expiry,
                scopes=GOOGLE_DEFAULT_SCOPES
            )
            db.add(credential)
        
        # Update session status
        session.status = "completed"
        
        logger.info(f"OAuth completed for {session.profile_id}")
        
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head><title>Authentication Successful</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #16a34a;">✓ Authentication Successful!</h1>
                <p>Account: <b>{session.profile_id}</b></p>
                <p>You have successfully authorized the application.</p>
                <p>You can now close this window and return to your assistant.</p>
                <script>
                    // Auto-close after 5 seconds
                    setTimeout(() => window.close(), 5000);
                </script>
            </body>
            </html>
            """,
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {e}")
        session.status = "failed"
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head><title>Error</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc2626;">✗ Error</h1>
                <p>An unexpected error occurred: {str(e)}</p>
                <p>Please try again.</p>
            </body>
            </html>
            """,
            status_code=500
        )


# ============================================
# GET /auth/status/{session_id}
# ============================================

@router.get(
    "/status/{session_id}",
    response_model=AuthStatusResponse,
    summary="Check OAuth status",
    description="Poll to check if OAuth flow completed."
)
async def get_auth_status(
    session_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Check status of OAuth session.
    Used by MCP servers to poll for completion.
    """
    result = await db.execute(
        select(OAuthSession).where(OAuthSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Check if expired
    if session.status == "pending" and session.expires_at < datetime.now(timezone.utc):
        session.status = "failed"
        await db.flush()
        
        return AuthStatusResponse(
            status="failed",
            session_id=session.id,
            error="Session expired"
        )
    
    response = AuthStatusResponse(
        status=session.status,
        session_id=session.id
    )
    
    if session.status == "completed":
        response.user_email = session.profile_id
        response.provider = session.provider_id
    elif session.status == "pending":
        response.expires_at = session.expires_at
    
    return response


# ============================================
# POST /auth/token
# ============================================

@router.post(
    "/token",
    response_model=TokenResponse,
    responses={
        401: {"model": TokenErrorResponse},
        404: {"model": TokenErrorResponse}
    },
    summary="Get access token",
    description="Get valid access token. Auto-refreshes if expired."
)
async def get_token(
    request: TokenRequest,
    db: AsyncSession = Depends(get_db_session),
    enc: EncryptionService = Depends(get_encryption_service),
    api_key: str = Depends(verify_api_key)
):
    """
    Get access token for user.
    
    1. Find credential by email + provider
    2. Check if token expired
    3. If expired, refresh using refresh_token
    4. Return decrypted access token
    """
    logger.info(f"Token request for {request.user_email}, provider {request.provider}")
    
    # Find credential
    result = await db.execute(
        select(OAuthCredential).where(
            and_(
                OAuthCredential.profile_id == request.user_email,
                OAuthCredential.provider_id == request.provider
            )
        )
    )
    credential = result.scalar_one_or_none()
    
    if not credential:
        logger.info(f"No credentials found for {request.user_email}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "not_authenticated",
                "message": f"No credentials found for {request.user_email}. Please authenticate.",
                "auth_required": True
            }
        )
    
    # Check if token needs refresh (expiry - buffer)
    now = datetime.now(timezone.utc)
    refresh_threshold = now + timedelta(seconds=settings.TOKEN_REFRESH_BUFFER_SECONDS)
    
    if credential.token_expiry and credential.token_expiry < refresh_threshold:
        logger.info(f"Token expired/expiring for {request.user_email}, refreshing...")
        
        if not credential.refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "refresh_failed",
                    "message": "No refresh token available. Please re-authenticate.",
                    "auth_required": True
                }
            )
        
        try:
            # Decrypt refresh token
            refresh_token = enc.decrypt(credential.refresh_token)
            
            # Call provider token endpoint
            async with httpx.AsyncClient() as client:
                refresh_response = await client.post(
                    GOOGLE_TOKEN_URL,
                    data={
                        "client_id": settings.GOOGLE_CLIENT_ID,
                        "client_secret": settings.GOOGLE_CLIENT_SECRET,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token"
                    }
                )
            
            if refresh_response.status_code != 200:
                logger.error(f"Token refresh failed: {refresh_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error": "refresh_failed",
                        "message": "Token refresh failed. Please re-authenticate.",
                        "auth_required": True
                    }
                )
            
            token_data = refresh_response.json()
            new_access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in", 3600)
            
            # Update credential
            credential.access_token = enc.encrypt(new_access_token)
            credential.token_expiry = now + timedelta(seconds=expires_in)
            
            # If new refresh token provided, update it
            if token_data.get("refresh_token"):
                credential.refresh_token = enc.encrypt(token_data["refresh_token"])
            
            await db.flush()
            
            logger.info(f"Token refreshed for {request.user_email}")
            
            return TokenResponse(
                access_token=new_access_token,
                token_type="Bearer",
                expires_at=credential.token_expiry,
                scopes=credential.scopes
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "refresh_failed",
                    "message": f"Token refresh error: {str(e)}",
                    "auth_required": True
                }
            )
    
    # Token is valid, decrypt and return
    try:
        access_token = enc.decrypt(credential.access_token)
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_at=credential.token_expiry,
            scopes=credential.scopes
        )
    except Exception as e:
        logger.error(f"Error decrypting token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt stored token"
        )


# ============================================
# GET /auth/providers/{user_email}
# ============================================

@router.get(
    "/providers/{user_email}",
    response_model=ProvidersListResponse,
    summary="List authorized providers",
    description="Get list of providers user has authenticated with."
)
async def list_providers(
    user_email: str,
    db: AsyncSession = Depends(get_db_session),
    api_key: str = Depends(verify_api_key)
):
    """
    List all providers user has authorized.
    """
    result = await db.execute(
        select(OAuthCredential).where(OAuthCredential.profile_id == user_email)
    )
    credentials = result.scalars().all()
    
    providers = [
        ProviderInfo(
            provider=cred.provider_id,
            scopes=cred.scopes,
            authenticated_at=cred.created_at,
            token_expires_at=cred.token_expiry
        )
        for cred in credentials
    ]
    
    return ProvidersListResponse(
        user_email=user_email,
        providers=providers
    )


# ============================================
# DELETE /auth/revoke
# ============================================

@router.delete(
    "/revoke",
    response_model=RevokeResponse,
    summary="Revoke credentials",
    description="Delete stored credentials for a user."
)
async def revoke_credentials(
    request: RevokeRequest,
    db: AsyncSession = Depends(get_db_session),
    api_key: str = Depends(verify_api_key)
):
    """
    Revoke (delete) stored credentials.
    """
    result = await db.execute(
        select(OAuthCredential).where(
            and_(
                OAuthCredential.profile_id == request.user_email,
                OAuthCredential.provider_id == request.provider
            )
        )
    )
    credential = result.scalar_one_or_none()
    
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No credentials found for {request.user_email} ({request.provider})"
        )
    
    await db.delete(credential)
    
    logger.info(f"Revoked credentials for {request.user_email} ({request.provider})")
    
    return RevokeResponse(
        success=True,
        message=f"Credentials revoked for {request.user_email} ({request.provider})"
    )
