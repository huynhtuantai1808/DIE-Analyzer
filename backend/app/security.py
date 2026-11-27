from datetime import datetime, timedelta, timezone
import uuid
from jose import jwt, JWTError
from pwdlib import PasswordHash
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_MINUTES
from .database import get_db
from .models import User, UserSession

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return password_hash.verify(password, hashed)

def create_token(user: User, jti: str | None = None, expires: datetime | None = None) -> str:
    token_jti = jti or uuid.uuid4().hex
    exp = expires or (datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES))
    return jwt.encode(
        {"sub": str(user.id), "username": user.username, "role": user.role, "jti": token_jti, "exp": exp},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                 detail="Phiên đăng nhập không hợp lệ hoặc đã bị thu hồi",
                                 headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub", ""))
        jti = payload.get("jti")
    except (JWTError, ValueError, TypeError):
        raise unauthorized
    if not jti:
        raise unauthorized

    session = db.query(UserSession).filter(UserSession.jti == jti, UserSession.user_id == user_id).first()
    now = datetime.now(timezone.utc)
    if not session or session.is_revoked or (session.expires_at and session.expires_at < now):
        raise unauthorized

    user = db.get(User, user_id)
    if not user:
        raise unauthorized
    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tài khoản của bạn đang bị tạm dừng hoạt động. Vui lòng liên hệ Administrator."
        )

    if not session.last_seen_at or (now - session.last_seen_at).total_seconds() >= 60:
        session.last_seen_at = now
        db.commit()

    user._session_jti = jti
    return user

def admin_user(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user
