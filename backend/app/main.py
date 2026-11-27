import csv
import hashlib
import io
import json
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Query, Request
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, text
from sqlalchemy.orm import Session, joinedload
from redis import Redis
from rq import Queue
from .config import UPLOAD_DIR, MAX_UPLOAD_MB, REDIS_URL, JWT_EXPIRE_MINUTES
from .database import Base, engine, get_db, SessionLocal
from .models import User, Scan, Setting, ActivityLog, UserSession
from .schemas import (
    UserCreate, UserLimitUpdate, UserPasswordReset, UserStatusUpdate, UserView, ScanView,
    SettingsView, SettingsUpdate, BatchDeleteRequest, CleanupRequest, StorageStatsView,
    ActivityLogView, LoginSummaryView, UserLoginSummaryItem, UserSessionView
)
from .security import hash_password, verify_password, create_token, current_user, admin_user
from .tasks import analyze_scan
from .report_pdf import generate_pdf_report

app = FastAPI(title="Detect It Easy Web API", version="1.0.0")
redis_conn = Redis.from_url(REDIS_URL)
queue = Queue("die-scans", connection=redis_conn, default_timeout=180)
LOCAL_TZ = ZoneInfo(os.getenv("TZ", "Asia/Ho_Chi_Minh"))

def get_client_ip(request: Request | None) -> str | None:
    if not request:
        return None
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()[:64]
    return request.client.host if request.client else None

def record_log(
    db: Session,
    *,
    username: str,
    action: str,
    category: str = "activity",
    status: str = "success",
    user_id: int | None = None,
    request: Request | None = None,
    target: str | None = None,
    details: str | None = None,
):
    """Persist a user activity or authentication event into activity_logs."""
    try:
        ip = get_client_ip(request)
        ua = (request.headers.get("user-agent") or "")[:512] if request else None
        entry = ActivityLog(
            user_id=user_id,
            username=(username or "unknown")[:80],
            action=action[:64],
            category=category[:32],
            status=status[:20],
            ip_address=ip,
            user_agent=ua,
            target=target[:255] if target else None,
            details=details,
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()

def get_db_setting(db: Session, key: str, default: str) -> str:
    s = db.get(Setting, key)
    return s.value if s else default

def _revoke_user_sessions(db: Session, user_id: int) -> int:
    now = datetime.now(timezone.utc)
    return (
        db.query(UserSession)
        .filter(UserSession.user_id == user_id, UserSession.is_revoked == False)  # noqa: E712
        .update({UserSession.is_revoked: True, UserSession.revoked_at: now}, synchronize_session=False)
    )

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS max_upload_mb INTEGER;"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;"))
        conn.commit()
    Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    try:
        username = os.getenv("ADMIN_USERNAME", "admin")
        if not db.query(User).filter(User.username == username).first():
            email = os.getenv("ADMIN_EMAIL", "admin@localhost")
            admin = User(username=username, email=email,
                         password_hash=hash_password(os.environ["ADMIN_PASSWORD"]), role="admin")
            db.add(admin)
            db.commit()

        if not db.get(Setting, "max_upload_mb"):
            db.add(Setting(key="max_upload_mb", value=str(MAX_UPLOAD_MB)))
            db.commit()
    finally:
        db.close()

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/auth/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        record_log(
            db,
            user_id=user.id if user else None,
            username=form.username or "unknown",
            action="LOGIN_FAILED",
            category="auth",
            status="failed",
            request=request,
            target=form.username,
            details="Sai tên đăng nhập hoặc mật khẩu",
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not getattr(user, "is_active", True):
        record_log(
            db,
            user_id=user.id,
            username=user.username,
            action="LOGIN_FAILED",
            category="auth",
            status="failed",
            request=request,
            target=user.username,
            details="Từ chối đăng nhập: Tài khoản đang bị tạm dừng hoạt động",
        )
        raise HTTPException(
            status_code=403,
            detail="Tài khoản của bạn đã bị tạm dừng hoạt động. Vui lòng liên hệ Administrator."
        )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    jti = uuid.uuid4().hex
    db_session = UserSession(
        jti=jti,
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        is_revoked=False,
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
    )
    db.add(db_session)
    db.commit()

    record_log(
        db,
        user_id=user.id,
        username=user.username,
        action="LOGIN_SUCCESS",
        category="auth",
        status="success",
        request=request,
        target=user.username,
        details=f"Đăng nhập thành công ({user.role})",
    )
    return {"access_token": create_token(user, jti=jti, expires=expires_at), "token_type": "bearer",
            "user": {"id": user.id, "username": user.username, "role": user.role}}

@app.post("/api/auth/logout")
def logout_endpoint(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    jti = getattr(user, "_session_jti", None)
    if jti:
        now = datetime.now(timezone.utc)
        db.query(UserSession).filter(UserSession.jti == jti, UserSession.user_id == user.id).update(
            {UserSession.is_revoked: True, UserSession.revoked_at: now},
            synchronize_session=False,
        )
        db.commit()
    record_log(
        db,
        user_id=user.id,
        username=user.username,
        action="LOGOUT",
        category="auth",
        status="success",
        request=request,
        target=user.username,
        details="Đăng xuất khỏi hệ thống",
    )
    return {"status": "ok"}

@app.get("/api/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    eff = user.max_upload_mb if (user.max_upload_mb and user.max_upload_mb > 0) else default_limit
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": getattr(user, "is_active", True),
        "max_upload_mb": user.max_upload_mb,
        "effective_limit_mb": eff
    }

@app.get("/api/users", response_model=list[UserView])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    users = db.query(User).order_by(User.id.desc()).all()
    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    user_stats = dict(
        (uid, (cnt, sz)) for uid, cnt, sz in db.query(
            Scan.user_id,
            func.count(Scan.id),
            func.coalesce(func.sum(Scan.size), 0)
        ).group_by(Scan.user_id).all()
    )
    results = []
    for u in users:
        cnt, sz = user_stats.get(u.id, (0, 0))
        eff = u.max_upload_mb if (u.max_upload_mb and u.max_upload_mb > 0) else default_limit
        results.append(UserView(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=getattr(u, "is_active", True),
            created_at=u.created_at,
            upload_count=cnt,
            total_upload_size=sz,
            max_upload_mb=u.max_upload_mb,
            effective_limit_mb=eff
        ))
    return results

@app.post("/api/users", response_model=UserView)
def create_user(request: Request, payload: UserCreate, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    if len(payload.password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")
    if payload.role not in ("admin", "analyst"):
        raise HTTPException(400, "Invalid role")
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(409, "Username or email already exists")
    limit = payload.max_upload_mb if (payload.max_upload_mb and payload.max_upload_mb > 0) else None
    user = User(username=payload.username, email=payload.email,
                password_hash=hash_password(payload.password), role=payload.role,
                max_upload_mb=limit)
    db.add(user)
    db.commit()
    db.refresh(user)
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="USER_CREATE",
        category="activity",
        status="success",
        request=request,
        target=user.username,
        details=f"Tạo tài khoản mới '{user.username}' (role={user.role}, limit={limit or 'mặc định'} MB)",
    )
    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    return UserView(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=getattr(user, "is_active", True),
        created_at=user.created_at,
        upload_count=0,
        total_upload_size=0,
        max_upload_mb=user.max_upload_mb,
        effective_limit_mb=user.max_upload_mb or default_limit
    )

@app.put("/api/users/{user_id}/limit", response_model=UserView)
def update_user_limit(request: Request, user_id: int, payload: UserLimitUpdate, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")
    if payload.max_upload_mb is not None and payload.max_upload_mb < 0:
        raise HTTPException(400, "Giới hạn upload không thể âm")
    if payload.max_upload_mb and payload.max_upload_mb > 4096:
        raise HTTPException(400, "Giới hạn upload tối đa 4096 MB")

    target_user.max_upload_mb = payload.max_upload_mb if (payload.max_upload_mb and payload.max_upload_mb > 0) else None
    db.commit()
    db.refresh(target_user)
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="USER_UPDATE_LIMIT",
        category="activity",
        status="success",
        request=request,
        target=target_user.username,
        details=f"Đặt giới hạn upload cho '{target_user.username}': {target_user.max_upload_mb or 'Mặc định'} MB",
    )

    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    cnt = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    sz = db.query(func.coalesce(func.sum(Scan.size), 0)).filter(Scan.user_id == user_id).scalar() or 0
    eff = target_user.max_upload_mb if target_user.max_upload_mb else default_limit

    return UserView(
        id=target_user.id,
        username=target_user.username,
        email=target_user.email,
        role=target_user.role,
        is_active=getattr(target_user, "is_active", True),
        created_at=target_user.created_at,
        upload_count=cnt,
        total_upload_size=sz,
        max_upload_mb=target_user.max_upload_mb,
        effective_limit_mb=eff
    )

@app.put("/api/users/{user_id}/status", response_model=UserView)
def update_user_status(request: Request, user_id: int, payload: UserStatusUpdate, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")
    if target_user.id == admin.id and not payload.is_active:
        raise HTTPException(400, "Không thể tự tạm dừng tài khoản quản trị đang đăng nhập")
    target_user.is_active = payload.is_active
    revoked_cnt = _revoke_user_sessions(db, user_id) if not payload.is_active else 0
    db.commit()
    db.refresh(target_user)
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="USER_ACTIVATE" if payload.is_active else "USER_SUSPEND",
        category="activity",
        status="success",
        request=request,
        target=target_user.username,
        details=f"{'Kích hoạt lại' if payload.is_active else 'Tạm dừng hoạt động'} tài khoản '{target_user.username}'"
        + (f" (thu hồi {revoked_cnt} phiên)" if revoked_cnt else ""),
    )
    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    cnt = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    sz = db.query(func.coalesce(func.sum(Scan.size), 0)).filter(Scan.user_id == user_id).scalar() or 0
    eff = target_user.max_upload_mb if target_user.max_upload_mb else default_limit
    return UserView(
        id=target_user.id,
        username=target_user.username,
        email=target_user.email,
        role=target_user.role,
        is_active=target_user.is_active,
        created_at=target_user.created_at,
        upload_count=cnt,
        total_upload_size=sz,
        max_upload_mb=target_user.max_upload_mb,
        effective_limit_mb=eff
    )

@app.delete("/api/users/{user_id}")
def delete_user(request: Request, user_id: int, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")
    if target_user.id == admin.id:
        raise HTTPException(400, "Không thể tự xóa tài khoản quản trị đang đăng nhập")

    target_username = target_user.username
    scans = db.query(Scan).filter(Scan.user_id == user_id).all()
    deleted_scans = 0
    freed_bytes = 0
    for s in scans:
        Path(UPLOAD_DIR, s.stored_name).unlink(missing_ok=True)
        freed_bytes += s.size or 0
        db.delete(s)
        deleted_scans += 1

    db.query(ActivityLog).filter(ActivityLog.user_id == user_id).update({ActivityLog.user_id: None}, synchronize_session=False)
    db.delete(target_user)
    db.commit()

    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="USER_DELETE",
        category="activity",
        status="success",
        request=request,
        target=target_username,
        details=f"Xóa vĩnh viễn tài khoản '{target_username}' cùng {deleted_scans} tệp quét ({freed_bytes:,} bytes giải phóng)",
    )
    return {
        "deleted": True,
        "username": target_username,
        "deleted_scans": deleted_scans,
        "freed_bytes": freed_bytes,
    }

@app.put("/api/users/{user_id}/password")
def reset_user_password(request: Request, user_id: int, payload: UserPasswordReset, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")
    if not payload.new_password or len(payload.new_password) < 12:
        raise HTTPException(400, "Mật khẩu mới phải có ít nhất 12 ký tự")
    target_user.password_hash = hash_password(payload.new_password)
    revoked_cnt = _revoke_user_sessions(db, user_id)
    db.commit()
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="USER_RESET_PASSWORD",
        category="activity",
        status="success",
        request=request,
        target=target_user.username,
        details=f"Admin đặt lại mật khẩu cho tài khoản '{target_user.username}'"
        + (f" (đã thu hồi {revoked_cnt} phiên cũ)" if revoked_cnt else ""),
    )
    return {"status": "ok", "message": f"Đã đặt lại mật khẩu cho tài khoản '{target_user.username}'"}

@app.post("/api/scans", response_model=list[ScanView])
async def upload_scans(request: Request, files: list[UploadFile] = File(...),
                       db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not files:
        raise HTTPException(400, "No files uploaded")
    if len(files) > 30:
        raise HTTPException(400, "Maximum 30 files per request")

    # Determine effective upload limit for this specific user (user-specific override or system default)
    default_limit_mb = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    effective_limit_mb = user.max_upload_mb if (user.max_upload_mb and user.max_upload_mb > 0) else default_limit_mb

    results = []
    for upload in files:
        original = Path(upload.filename or "unnamed.bin").name[:512]
        stored = f"{uuid.uuid4().hex}.sample"
        destination = Path(UPLOAD_DIR) / stored
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        size = 0
        try:
            with destination.open("wb") as out:
                while chunk := await upload.read(1024 * 1024):
                    size += len(chunk)
                    if size > effective_limit_mb * 1024 * 1024:
                        limit_desc = f"giới hạn riêng {effective_limit_mb} MB của tài khoản '{user.username}'" if user.max_upload_mb else f"giới hạn mặc định {effective_limit_mb} MB của hệ thống"
                        record_log(
                            db,
                            user_id=user.id,
                            username=user.username,
                            action="UPLOAD_SCAN",
                            category="activity",
                            status="failed",
                            request=request,
                            target=original,
                            details=f"Từ chối tải lên: vượt quá {limit_desc}",
                        )
                        raise HTTPException(413, f"{original}: vượt quá {limit_desc}")
                    md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                    out.write(chunk)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        finally:
            await upload.close()
        scan = Scan(user_id=user.id, original_name=original, stored_name=stored, size=size,
                    md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest(),
                    status="queued")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        try:
            queue.enqueue(analyze_scan, scan.id, job_timeout=180, result_ttl=86400)
        except Exception as exc:
            scan.status = "failed"
            scan.error = f"Queue unavailable: {exc}"
            db.commit()
        results.append(scan)

    if results:
        names = ", ".join(s.original_name for s in results[:5])
        if len(results) > 5:
            names += f" (+{len(results) - 5} tệp)"
        total_bytes = sum(s.size for s in results)
        record_log(
            db,
            user_id=user.id,
            username=user.username,
            action="UPLOAD_SCAN",
            category="activity",
            status="success",
            request=request,
            target=names,
            details=f"Tải lên {len(results)} tệp tin ({total_bytes:,} bytes)",
        )
    return results

@app.get("/api/settings", response_model=SettingsView)
def get_settings(db: Session = Depends(get_db), _: User = Depends(current_user)):
    limit_mb = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    return SettingsView(max_upload_mb=limit_mb, upload_path=UPLOAD_DIR)

@app.put("/api/settings", response_model=SettingsView)
def update_settings(request: Request, payload: SettingsUpdate, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    if payload.max_upload_mb < 1 or payload.max_upload_mb > 2048:
        raise HTTPException(400, "Giới hạn dung lượng tải lên phải nằm trong khoảng từ 1 MB đến 2048 MB")
    setting = db.get(Setting, "max_upload_mb")
    if not setting:
        setting = Setting(key="max_upload_mb", value=str(payload.max_upload_mb))
        db.add(setting)
    else:
        setting.value = str(payload.max_upload_mb)
    db.commit()
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="SETTINGS_UPDATE",
        category="activity",
        status="success",
        request=request,
        target="max_upload_mb",
        details=f"Cập nhật giới hạn upload mặc định hệ thống thành {payload.max_upload_mb} MB",
    )
    return SettingsView(max_upload_mb=payload.max_upload_mb, upload_path=UPLOAD_DIR)

@app.get("/api/scans", response_model=list[ScanView])
def scan_history(q: str | None = Query(default=None), status: str | None = None,
                 user_id: int | None = None,
                 limit: int = Query(default=100, ge=1, le=500),
                 db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(Scan).options(joinedload(Scan.user))
    if user.role != "admin":
        query = query.filter(Scan.user_id == user.id)
    elif user_id is not None:
        query = query.filter(Scan.user_id == user_id)
    if status:
        query = query.filter(Scan.status == status)
    if q:
        query = query.filter((Scan.original_name.ilike(f"%{q}%")) | (Scan.sha256.ilike(f"%{q}%")))
    return query.order_by(Scan.created_at.desc()).limit(limit).all()

@app.get("/api/scans/{scan_id}", response_model=ScanView)
def scan_detail(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.query(Scan).options(joinedload(Scan.user)).filter(Scan.id == scan_id).first()
    if not scan or (user.role != "admin" and scan.user_id != user.id):
        raise HTTPException(404, "Scan not found")
    return scan

@app.get("/api/scans/{scan_id}/pdf")
def export_scan_pdf(request: Request, scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.query(Scan).options(joinedload(Scan.user)).filter(Scan.id == scan_id).first()
    if not scan or (user.role != "admin" and scan.user_id != user.id):
        raise HTTPException(404, "Scan not found")
    if scan.status not in ("completed", "failed"):
        raise HTTPException(400, "Báo cáo PDF chỉ khả dụng sau khi quét hoàn tất")

    pdf_bytes = generate_pdf_report(scan)
    safe_name = "".join(c for c in scan.original_name if c.isalnum() or c in "._- ")[:64] or "file"
    record_log(
        db,
        user_id=user.id,
        username=user.username,
        action="EXPORT_PDF",
        category="activity",
        status="success",
        request=request,
        target=scan.original_name,
        details=f"Xuất báo cáo PDF cho scan #{scan.id}",
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="DIE-Report-{scan.id}-{safe_name}.pdf"'
        }
    )

@app.delete("/api/scans/{scan_id}")
def delete_scan(request: Request, scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.get(Scan, scan_id)
    if not scan or (user.role != "admin" and scan.user_id != user.id):
        raise HTTPException(404, "Scan not found")
    orig_name = scan.original_name
    Path(UPLOAD_DIR, scan.stored_name).unlink(missing_ok=True)
    db.delete(scan)
    db.commit()
    record_log(
        db,
        user_id=user.id,
        username=user.username,
        action="DELETE_SCAN",
        category="activity",
        status="success",
        request=request,
        target=orig_name,
        details=f"Xóa tệp tin #{scan_id} ({orig_name})",
    )
    return {"deleted": True, "id": scan_id}

@app.post("/api/scans/delete-batch")
def batch_delete_scans(request: Request, payload: BatchDeleteRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not payload.scan_ids:
        return {"deleted_count": 0, "freed_bytes": 0}
    query = db.query(Scan).filter(Scan.id.in_(payload.scan_ids))
    if user.role != "admin":
        query = query.filter(Scan.user_id == user.id)
    scans = query.all()
    deleted_count = 0
    freed_bytes = 0
    names = []
    for scan in scans:
        Path(UPLOAD_DIR, scan.stored_name).unlink(missing_ok=True)
        freed_bytes += scan.size or 0
        names.append(scan.original_name)
        db.delete(scan)
        deleted_count += 1
    db.commit()
    if deleted_count > 0:
        record_log(
            db,
            user_id=user.id,
            username=user.username,
            action="BATCH_DELETE_SCANS",
            category="activity",
            status="success",
            request=request,
            target=", ".join(names[:5]),
            details=f"Xóa hàng loạt {deleted_count} tệp tin ({freed_bytes:,} bytes giải phóng)",
        )
    return {"deleted_count": deleted_count, "freed_bytes": freed_bytes}

@app.get("/api/admin/storage-stats", response_model=StorageStatsView)
def storage_stats(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    total_db_size = db.query(func.coalesce(func.sum(Scan.size), 0)).scalar() or 0

    status_rows = db.query(Scan.status, func.count(Scan.id)).group_by(Scan.status).all()
    status_counts = {st: cnt for st, cnt in status_rows}

    upload_dir = Path(UPLOAD_DIR)
    disk_files_count = 0
    disk_used_bytes = 0
    orphan_files_count = 0

    known_stored = set(x[0] for x in db.query(Scan.stored_name).all())
    if upload_dir.exists():
        for f in upload_dir.iterdir():
            if f.is_file() and f.name != ".gitkeep":
                disk_files_count += 1
                try:
                    disk_used_bytes += f.stat().st_size
                except Exception:
                    pass
                if f.name not in known_stored:
                    orphan_files_count += 1

    return StorageStatsView(
        total_scans=total_scans,
        total_db_size=total_db_size,
        disk_files_count=disk_files_count,
        disk_used_bytes=disk_used_bytes,
        orphan_files_count=orphan_files_count,
        status_counts=status_counts
    )

@app.post("/api/admin/cleanup")
def admin_cleanup(request: Request, payload: CleanupRequest, db: Session = Depends(get_db), admin: User = Depends(admin_user)):
    deleted_count = 0
    freed_bytes = 0
    orphans_deleted = 0
    upload_dir = Path(UPLOAD_DIR)

    if payload.mode == "failed":
        scans = db.query(Scan).filter(Scan.status == "failed").all()
        for s in scans:
            (upload_dir / s.stored_name).unlink(missing_ok=True)
            freed_bytes += s.size or 0
            db.delete(s)
            deleted_count += 1
        db.commit()

    elif payload.mode == "older_than":
        days = payload.days or 30
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        scans = db.query(Scan).filter(Scan.created_at < cutoff).all()
        for s in scans:
            (upload_dir / s.stored_name).unlink(missing_ok=True)
            freed_bytes += s.size or 0
            db.delete(s)
            deleted_count += 1
        db.commit()

    elif payload.mode == "user":
        if not payload.user_id:
            raise HTTPException(400, "Vui lòng chọn người dùng cần dọn dẹp")
        scans = db.query(Scan).filter(Scan.user_id == payload.user_id).all()
        for s in scans:
            (upload_dir / s.stored_name).unlink(missing_ok=True)
            freed_bytes += s.size or 0
            db.delete(s)
            deleted_count += 1
        db.commit()

    elif payload.mode == "all":
        scans = db.query(Scan).all()
        for s in scans:
            (upload_dir / s.stored_name).unlink(missing_ok=True)
            freed_bytes += s.size or 0
            db.delete(s)
            deleted_count += 1
        db.commit()

    elif payload.mode == "orphans":
        known_stored = set(x[0] for x in db.query(Scan.stored_name).all())
        if upload_dir.exists():
            for f in upload_dir.iterdir():
                if f.is_file() and f.name not in known_stored and f.name != ".gitkeep":
                    try:
                        sz = f.stat().st_size
                        f.unlink(missing_ok=True)
                        orphans_deleted += 1
                        freed_bytes += sz
                    except Exception:
                        pass
    else:
        raise HTTPException(400, f"Chế độ dọn dẹp không hợp lệ: {payload.mode}")

    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="ADMIN_CLEANUP",
        category="activity",
        status="success",
        request=request,
        target=payload.mode,
        details=f"Dọn dẹp chế độ '{payload.mode}': {deleted_count} bản ghi, {orphans_deleted} file rác, giải phóng {freed_bytes:,} bytes",
    )

    return {
        "mode": payload.mode,
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "orphans_deleted": orphans_deleted
    }


def _build_logs_query(
    db: Session,
    category: str | None = None,
    user_id: int | None = None,
    action: str | None = None,
    status: str | None = None,
    q: str | None = None,
    days: int | None = None,
):
    query = db.query(ActivityLog)
    if category:
        query = query.filter(ActivityLog.category == category)
    if user_id is not None:
        query = query.filter(ActivityLog.user_id == user_id)
    if action:
        query = query.filter(ActivityLog.action == action)
    if status:
        query = query.filter(ActivityLog.status == status)
    if days and days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(ActivityLog.created_at >= cutoff)
    if q:
        like = f"%{q}%"
        query = query.filter(
            (ActivityLog.username.ilike(like))
            | (ActivityLog.ip_address.ilike(like))
            | (ActivityLog.target.ilike(like))
            | (ActivityLog.details.ilike(like))
            | (ActivityLog.action.ilike(like))
        )
    return query.order_by(ActivityLog.created_at.desc())


@app.get("/api/admin/logs", response_model=list[ActivityLogView])
def list_activity_logs(
    category: str | None = None,
    user_id: int | None = None,
    action: str | None = None,
    status: str | None = None,
    q: str | None = None,
    days: int | None = None,
    limit: int = Query(default=250, ge=1, le=2000),
    db: Session = Depends(get_db),
    _: User = Depends(admin_user),
):
    return _build_logs_query(db, category, user_id, action, status, q, days).limit(limit).all()


@app.get("/api/admin/logs/summary", response_model=LoginSummaryView)
def get_login_summary(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    total_logs = db.query(func.count(ActivityLog.id)).scalar() or 0
    total_logins = (
        db.query(func.count(ActivityLog.id))
        .filter(ActivityLog.action.in_(["LOGIN_SUCCESS", "LOGIN_FAILED"]))
        .scalar()
        or 0
    )
    login_success_24h = (
        db.query(func.count(ActivityLog.id))
        .filter(ActivityLog.action == "LOGIN_SUCCESS", ActivityLog.created_at >= cutoff_24h)
        .scalar()
        or 0
    )
    login_failed_24h = (
        db.query(func.count(ActivityLog.id))
        .filter(ActivityLog.action == "LOGIN_FAILED", ActivityLog.created_at >= cutoff_24h)
        .scalar()
        or 0
    )
    active_users_24h = (
        db.query(func.count(func.distinct(ActivityLog.username)))
        .filter(ActivityLog.action == "LOGIN_SUCCESS", ActivityLog.created_at >= cutoff_24h)
        .scalar()
        or 0
    )

    users = db.query(User).order_by(User.id.asc()).all()
    auth_logs = (
        db.query(ActivityLog)
        .filter(ActivityLog.action.in_(["LOGIN_SUCCESS", "LOGIN_FAILED"]))
        .order_by(ActivityLog.created_at.desc())
        .all()
    )

    by_user: dict[str, dict] = {}
    for entry in auth_logs:
        stat = by_user.setdefault(entry.username, {
            "last_login_at": None,
            "last_login_ip": None,
            "last_login_ua": None,
            "login_count": 0,
            "failed_count": 0,
        })
        if entry.action == "LOGIN_SUCCESS":
            stat["login_count"] += 1
            if stat["last_login_at"] is None:
                stat["last_login_at"] = entry.created_at
                stat["last_login_ip"] = entry.ip_address
                stat["last_login_ua"] = entry.user_agent
        elif entry.action == "LOGIN_FAILED":
            stat["failed_count"] += 1

    now = datetime.now(timezone.utc)
    active_counts = dict(
        db.query(UserSession.user_id, func.count(UserSession.id))
        .filter(UserSession.is_revoked == False, UserSession.expires_at > now)  # noqa: E712
        .group_by(UserSession.user_id)
        .all()
    )

    user_sessions = []
    for u in users:
        st = by_user.get(u.username, {})
        user_sessions.append(UserLoginSummaryItem(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=getattr(u, "is_active", True),
            last_login_at=st.get("last_login_at"),
            last_login_ip=st.get("last_login_ip"),
            last_login_ua=st.get("last_login_ua"),
            login_count=st.get("login_count", 0),
            failed_count=st.get("failed_count", 0),
            active_sessions_count=active_counts.get(u.id, 0),
        ))

    return LoginSummaryView(
        total_logs=total_logs,
        login_success_24h=login_success_24h,
        login_failed_24h=login_failed_24h,
        active_users_24h=active_users_24h,
        total_logins=total_logins,
        user_sessions=user_sessions,
    )


@app.get("/api/admin/sessions", response_model=list[UserSessionView])
def list_user_sessions(
    active_only: bool = True,
    user_id: int | None = None,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_user),
):
    now = datetime.now(timezone.utc)
    current_jti = getattr(admin, "_session_jti", None)
    query = db.query(UserSession).options(joinedload(UserSession.user))
    if active_only:
        query = query.filter(UserSession.is_revoked == False, UserSession.expires_at > now)  # noqa: E712
    if user_id is not None:
        query = query.filter(UserSession.user_id == user_id)
    rows = query.order_by(UserSession.last_seen_at.desc()).limit(200).all()
    return [
        UserSessionView(
            id=s.id,
            jti=s.jti,
            user_id=s.user_id,
            username=s.user.username if s.user else "Unknown",
            role=s.user.role if s.user else "analyst",
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            is_revoked=s.is_revoked,
            created_at=s.created_at,
            last_seen_at=s.last_seen_at,
            expires_at=s.expires_at,
            revoked_at=s.revoked_at,
            is_current=(s.jti == current_jti),
        )
        for s in rows
    ]


@app.post("/api/admin/sessions/{session_id}/revoke")
def revoke_single_session(
    request: Request,
    session_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_user),
):
    session = db.get(UserSession, session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    if session.jti == getattr(admin, "_session_jti", None):
        raise HTTPException(400, "Không thể tự thu hồi phiên đăng nhập hiện tại của chính bạn")
    if not session.is_revoked:
        session.is_revoked = True
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()
    target_user = db.get(User, session.user_id)
    uname = target_user.username if target_user else f"user#{session.user_id}"
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="SESSION_REVOKE",
        category="auth",
        status="success",
        request=request,
        target=uname,
        details=f"Admin thu hồi phiên đăng nhập #{session_id} của '{uname}' (IP: {session.ip_address or '—'})",
    )
    return {"revoked": True, "session_id": session_id}


@app.post("/api/admin/users/{user_id}/revoke-sessions")
def revoke_all_user_sessions(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_user),
):
    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(404, "User not found")
    now = datetime.now(timezone.utc)
    current_jti = getattr(admin, "_session_jti", None)
    query = db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.is_revoked == False)  # noqa: E712
    if user_id == admin.id and current_jti:
        query = query.filter(UserSession.jti != current_jti)
    revoked_count = query.update({UserSession.is_revoked: True, UserSession.revoked_at: now}, synchronize_session=False)
    db.commit()
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="SESSION_REVOKE_ALL",
        category="auth",
        status="success",
        request=request,
        target=target_user.username,
        details=f"Admin đăng xuất tất cả {revoked_count} phiên đang hoạt động của '{target_user.username}'",
    )
    return {"revoked_count": revoked_count, "username": target_user.username}


@app.get("/api/admin/logs/export")
def export_activity_logs(
    request: Request,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    category: str | None = None,
    user_id: int | None = None,
    action: str | None = None,
    status: str | None = None,
    q: str | None = None,
    days: int | None = None,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_user),
):
    rows = _build_logs_query(db, category, user_id, action, status, q, days).limit(5000).all()
    stamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d-%H%M%S")
    prefix = "login-logs" if category == "auth" else "activity-logs"

    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="EXPORT_LOGS",
        category="activity",
        status="success",
        request=request,
        target=f"{prefix}-{stamp}.{format}",
        details=f"Xuất {len(rows)} dòng nhật ký định dạng {format.upper()}",
    )

    if format == "json":
        payload = [
            {
                "id": r.id,
                "time": r.created_at.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %z") if r.created_at else None,
                "username": r.username,
                "user_id": r.user_id,
                "category": r.category,
                "action": r.action,
                "status": r.status,
                "ip_address": r.ip_address,
                "target": r.target,
                "details": r.details,
                "user_agent": r.user_agent,
            }
            for r in rows
        ]
        return Response(
            content=json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{prefix}-{stamp}.json"'},
        )

    buf = io.StringIO()
    buf.write("\ufeff")  # UTF-8 BOM for Microsoft Excel compatibility
    writer = csv.writer(buf)
    writer.writerow([
        "ID", "Thời gian (+07:00)", "Tên đăng nhập", "User ID",
        "Phân loại", "Hành động", "Trạng thái", "Địa chỉ IP",
        "Đối tượng", "Chi tiết", "User-Agent"
    ])
    for r in rows:
        t_str = r.created_at.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S") if r.created_at else ""
        writer.writerow([
            r.id, t_str, r.username, r.user_id or "",
            r.category, r.action, r.status, r.ip_address or "",
            r.target or "", r.details or "", r.user_agent or ""
        ])
    return Response(
        content=buf.getvalue().encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{prefix}-{stamp}.csv"'},
    )


@app.delete("/api/admin/logs")
def clear_old_logs(
    request: Request,
    days: int | None = Query(default=None, ge=1, le=3650),
    category: str | None = None,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_user),
):
    query = db.query(ActivityLog)
    if category:
        query = query.filter(ActivityLog.category == category)
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(ActivityLog.created_at < cutoff)
    deleted = query.delete(synchronize_session=False)
    db.commit()
    record_log(
        db,
        user_id=admin.id,
        username=admin.username,
        action="CLEAR_LOGS",
        category="activity",
        status="success",
        request=request,
        target=category or "all",
        details=f"Đã xóa {deleted} bản ghi nhật ký" + (f" cũ hơn {days} ngày" if days else ""),
    )
    return {"deleted_count": deleted}
