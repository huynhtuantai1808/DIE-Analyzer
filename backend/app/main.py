import hashlib
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Query
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, text
from sqlalchemy.orm import Session, joinedload
from redis import Redis
from rq import Queue
from .config import UPLOAD_DIR, MAX_UPLOAD_MB, REDIS_URL
from .database import Base, engine, get_db, SessionLocal
from .models import User, Scan, Setting
from .schemas import (
    UserCreate, UserLimitUpdate, UserView, ScanView, SettingsView, SettingsUpdate,
    BatchDeleteRequest, CleanupRequest, StorageStatsView
)
from .security import hash_password, verify_password, create_token, current_user, admin_user
from .tasks import analyze_scan
from .report_pdf import generate_pdf_report

app = FastAPI(title="Detect It Easy Web API", version="1.0.0")
redis_conn = Redis.from_url(REDIS_URL)
queue = Queue("die-scans", connection=redis_conn, default_timeout=180)

def get_db_setting(db: Session, key: str, default: str) -> str:
    s = db.get(Setting, key)
    return s.value if s else default

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS max_upload_mb INTEGER;"))
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
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"access_token": create_token(user), "token_type": "bearer",
            "user": {"id": user.id, "username": user.username, "role": user.role}}

@app.get("/api/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    eff = user.max_upload_mb if (user.max_upload_mb and user.max_upload_mb > 0) else default_limit
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
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
            created_at=u.created_at,
            upload_count=cnt,
            total_upload_size=sz,
            max_upload_mb=u.max_upload_mb,
            effective_limit_mb=eff
        ))
    return results

@app.post("/api/users", response_model=UserView)
def create_user(payload: UserCreate, db: Session = Depends(get_db), _: User = Depends(admin_user)):
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
    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    return UserView(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        created_at=user.created_at,
        upload_count=0,
        total_upload_size=0,
        max_upload_mb=user.max_upload_mb,
        effective_limit_mb=user.max_upload_mb or default_limit
    )

@app.put("/api/users/{user_id}/limit", response_model=UserView)
def update_user_limit(user_id: int, payload: UserLimitUpdate, db: Session = Depends(get_db), _: User = Depends(admin_user)):
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

    default_limit = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    cnt = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar() or 0
    sz = db.query(func.coalesce(func.sum(Scan.size), 0)).filter(Scan.user_id == user_id).scalar() or 0
    eff = target_user.max_upload_mb if target_user.max_upload_mb else default_limit

    return UserView(
        id=target_user.id,
        username=target_user.username,
        email=target_user.email,
        role=target_user.role,
        created_at=target_user.created_at,
        upload_count=cnt,
        total_upload_size=sz,
        max_upload_mb=target_user.max_upload_mb,
        effective_limit_mb=eff
    )

@app.post("/api/scans", response_model=list[ScanView])
async def upload_scans(files: list[UploadFile] = File(...),
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
    return results

@app.get("/api/settings", response_model=SettingsView)
def get_settings(db: Session = Depends(get_db), _: User = Depends(current_user)):
    limit_mb = int(get_db_setting(db, "max_upload_mb", str(MAX_UPLOAD_MB)))
    return SettingsView(max_upload_mb=limit_mb, upload_path=UPLOAD_DIR)

@app.put("/api/settings", response_model=SettingsView)
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db), _: User = Depends(admin_user)):
    if payload.max_upload_mb < 1 or payload.max_upload_mb > 2048:
        raise HTTPException(400, "Giới hạn dung lượng tải lên phải nằm trong khoảng từ 1 MB đến 2048 MB")
    setting = db.get(Setting, "max_upload_mb")
    if not setting:
        setting = Setting(key="max_upload_mb", value=str(payload.max_upload_mb))
        db.add(setting)
    else:
        setting.value = str(payload.max_upload_mb)
    db.commit()
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
def export_scan_pdf(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.query(Scan).options(joinedload(Scan.user)).filter(Scan.id == scan_id).first()
    if not scan or (user.role != "admin" and scan.user_id != user.id):
        raise HTTPException(404, "Scan not found")
    if scan.status not in ("completed", "failed"):
        raise HTTPException(400, "Báo cáo PDF chỉ khả dụng sau khi quét hoàn tất")

    pdf_bytes = generate_pdf_report(scan)
    safe_name = "".join(c for c in scan.original_name if c.isalnum() or c in "._- ")[:64] or "file"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="DIE-Report-{scan.id}-{safe_name}.pdf"'
        }
    )

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.get(Scan, scan_id)
    if not scan or (user.role != "admin" and scan.user_id != user.id):
        raise HTTPException(404, "Scan not found")
    Path(UPLOAD_DIR, scan.stored_name).unlink(missing_ok=True)
    db.delete(scan)
    db.commit()
    return {"deleted": True, "id": scan_id}

@app.post("/api/scans/delete-batch")
def batch_delete_scans(payload: BatchDeleteRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not payload.scan_ids:
        return {"deleted_count": 0, "freed_bytes": 0}
    query = db.query(Scan).filter(Scan.id.in_(payload.scan_ids))
    if user.role != "admin":
        query = query.filter(Scan.user_id == user.id)
    scans = query.all()
    deleted_count = 0
    freed_bytes = 0
    for scan in scans:
        Path(UPLOAD_DIR, scan.stored_name).unlink(missing_ok=True)
        freed_bytes += scan.size or 0
        db.delete(scan)
        deleted_count += 1
    db.commit()
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
def admin_cleanup(payload: CleanupRequest, db: Session = Depends(get_db), _: User = Depends(admin_user)):
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

    return {
        "mode": payload.mode,
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "orphans_deleted": orphans_deleted
    }
