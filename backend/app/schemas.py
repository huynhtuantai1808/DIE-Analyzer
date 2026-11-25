from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "analyst"
    max_upload_mb: int | None = None

class UserLimitUpdate(BaseModel):
    max_upload_mb: int | None = None

class UserView(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime
    upload_count: int = 0
    total_upload_size: int = 0
    max_upload_mb: int | None = None
    effective_limit_mb: int | None = None
    model_config = ConfigDict(from_attributes=True)

class ScanView(BaseModel):
    id: int
    original_name: str
    size: int
    md5: str
    sha1: str
    sha256: str
    status: str
    result: dict | None
    raw_output: str | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None
    user_id: int | None = None
    uploader: str | None = None
    model_config = ConfigDict(from_attributes=True)

class SettingsView(BaseModel):
    max_upload_mb: int
    upload_path: str

class SettingsUpdate(BaseModel):
    max_upload_mb: int

class BatchDeleteRequest(BaseModel):
    scan_ids: list[int]

class CleanupRequest(BaseModel):
    mode: str  # "failed", "older_than", "user", "all", "orphans"
    days: int | None = None
    user_id: int | None = None

class StorageStatsView(BaseModel):
    total_scans: int
    total_db_size: int
    disk_files_count: int
    disk_used_bytes: int
    orphan_files_count: int
    status_counts: dict[str, int]

