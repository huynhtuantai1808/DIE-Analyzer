import logging
import os
from datetime import datetime, timezone, timedelta
from uvicorn.logging import DefaultFormatter, AccessFormatter

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo(os.getenv("TZ", "Asia/Ho_Chi_Minh"))
except Exception:
    _TZ = timezone(timedelta(hours=7))


class LocalTimeMixin:
    """Format log timestamps in the configured local timezone."""
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=_TZ)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.strftime("%Y-%m-%d %H:%M:%S")


class LocalTimeDefaultFormatter(LocalTimeMixin, DefaultFormatter):
    pass


class LocalTimeAccessFormatter(LocalTimeMixin, AccessFormatter):
    pass


class NoiseFilter(logging.Filter):
    """Filter out noisy background polling and healthcheck access logs when HTTP status is 2xx/3xx."""
    def filter(self, record: logging.LogRecord) -> bool:
        args = getattr(record, "args", None)
        if isinstance(args, tuple) and len(args) >= 5:
            method = str(args[1]).upper()
            path = str(args[2])
            try:
                status_code = int(args[4])
            except (TypeError, ValueError):
                status_code = 0
        else:
            msg = record.getMessage()
            if '"GET /api/scans?limit=' in msg and (' 200' in msg or ' 304' in msg):
                return False
            if '"GET /api/health' in msg and (' 200' in msg or ' 304' in msg):
                return False
            return True

        if method == "GET" and 200 <= status_code < 400:
            if path == "/api/health" or path.startswith("/api/health?"):
                return False
            if path.startswith("/api/scans"):
                if "poll=1" in path or ("q=" not in path and "user_id=" not in path):
                    return False
        return True
