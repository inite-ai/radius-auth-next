"""JWT service for token generation and validation."""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidTokenError

from app.config.settings import settings
from app.utils.exceptions import InvalidTokenError as CustomInvalidTokenError
from app.utils.exceptions import TokenExpiredError


class JWTService:
    """Service for JWT token operations."""
    
    def __init__(self):
        self.algorithm = settings.JWT_ALGORITHM
        self.access_token_expire_minutes = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    
    def _get_private_key(self) -> str:
        """Get private key for signing tokens."""
        if self.algorithm == "HS256":
            return settings.JWT_SECRET_KEY
        
        private_key = settings.JWT_PRIVATE_KEY
        if not private_key:
            raise ValueError("JWT private key not configured")
        return private_key
    
    def _get_public_key(self) -> str:
        """Get public key for verifying tokens."""
        if self.algorithm == "HS256":
            return settings.JWT_SECRET_KEY
        
        public_key = settings.JWT_PUBLIC_KEY
        if not public_key:
            raise ValueError("JWT public key not configured")
        return public_key
    
    def create_access_token(
        self,
        user_id: int,
        email: str,
        organization_id: Optional[int] = None,
        scopes: Optional[list] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        session_id: Optional[int] = None,
    ) -> str:
        """Create a JWT access token."""
        now = datetime.utcnow()
        expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        payload = {
            "sub": str(user_id),  # Subject (user ID)
            "email": email,
            "type": "access",
            "iat": now,  # Issued at
            "exp": expire,  # Expiration time
            "iss": "platform-auth",  # Issuer
            "aud": "platform-api",  # Audience
        }
        
        if organization_id:
            payload["org_id"] = organization_id
        
        if scopes:
            payload["scopes"] = scopes
        
        if session_id:
            payload["session_id"] = session_id
        
        if extra_claims:
            payload.update(extra_claims)
        
        return jwt.encode(
            payload,
            self._get_private_key(),
            algorithm=self.algorithm,
        )
    
    def create_refresh_token(
        self,
        user_id: int,
        session_id: str,
        device_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a JWT refresh token."""
        now = datetime.utcnow()
        expire = now + timedelta(days=self.refresh_token_expire_days)
        
        payload = {
            "sub": str(user_id),
            "session_id": session_id,
            "type": "refresh",
            "iat": now,
            "exp": expire,
            "iss": "platform-auth",
            "aud": "platform-auth",  # Refresh tokens only for auth service
        }
        
        if device_info:
            payload["device"] = device_info
        
        return jwt.encode(
            payload,
            self._get_private_key(),
            algorithm=self.algorithm,
        )
    
    def decode_token(self, token: str, verify_exp: bool = True) -> Dict[str, Any]:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self._get_public_key(),
                algorithms=[self.algorithm],
                options={"verify_exp": verify_exp},
                audience=["platform-api", "platform-auth"],
                issuer="platform-auth",
            )
            return payload
        
        except ExpiredSignatureError:
            raise TokenExpiredError("Token has expired")
        
        except (DecodeError, InvalidTokenError) as e:
            raise CustomInvalidTokenError(f"Invalid token: {e}")
    
    def decode_access_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate an access token."""
        payload = self.decode_token(token)
        
        if payload.get("type") != "access":
            raise CustomInvalidTokenError("Invalid token type")
        
        return payload
    
    def decode_refresh_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate a refresh token."""
        payload = self.decode_token(token)
        
        if payload.get("type") != "refresh":
            raise CustomInvalidTokenError("Invalid token type")
        
        return payload
    
    def get_user_id_from_token(self, token: str) -> int:
        """Extract user ID from token."""
        payload = self.decode_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise CustomInvalidTokenError("Token missing user ID")
        
        try:
            return int(user_id)
        except ValueError:
            raise CustomInvalidTokenError("Invalid user ID in token")
    
    def get_session_id_from_refresh_token(self, token: str) -> str:
        """Extract session ID from refresh token."""
        payload = self.decode_refresh_token(token)
        session_id = payload.get("session_id")
        
        if not session_id:
            raise CustomInvalidTokenError("Token missing session ID")
        
        return session_id
    
    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired without raising exception."""
        try:
            self.decode_token(token, verify_exp=True)
            return False
        except TokenExpiredError:
            return True
        except CustomInvalidTokenError:
            return True  # Invalid tokens are considered expired
    
    def get_token_expiration(self, token: str) -> Optional[datetime]:
        """Get token expiration time."""
        try:
            payload = self.decode_token(token, verify_exp=False)
            exp = payload.get("exp")
            if exp:
                return datetime.fromtimestamp(exp)
            return None
        except CustomInvalidTokenError:
            return None
    
    def create_password_reset_token(self, user_id: int, email: str) -> str:
        """Create a password reset token."""
        now = datetime.utcnow()
        expire = now + timedelta(hours=1)  # Reset tokens expire in 1 hour
        
        payload = {
            "sub": str(user_id),
            "email": email,
            "type": "password_reset",
            "iat": now,
            "exp": expire,
            "iss": "platform-auth",
            "aud": "platform-auth",
        }
        
        return jwt.encode(
            payload,
            self._get_private_key(),
            algorithm=self.algorithm,
        )
    
    def create_email_verification_token(self, user_id: int, email: str) -> str:
        """Create an email verification token."""
        now = datetime.utcnow()
        expire = now + timedelta(days=7)  # Verification tokens expire in 7 days
        
        payload = {
            "sub": str(user_id),
            "email": email,
            "type": "email_verification",
            "iat": now,
            "exp": expire,
            "iss": "platform-auth",
            "aud": "platform-auth",
        }
        
        return jwt.encode(
            payload,
            self._get_private_key(),
            algorithm=self.algorithm,
        )
