# Detect It Easy Web GUI

A Docker Compose web dashboard for **static** binary triage using the official Detect It Easy command-line tool (`diec`).

## Included

- React dashboard: overview, multi-file upload, scan history, report details, hashes.
- FastAPI REST API with JWT authentication.
- Admin-seeded user management (`admin` and `analyst` roles).
- PostgreSQL persistence and Redis/RQ background queue.
- DIE CLI invoked as `diec -b -j <sample>`.
- Docker containers run as non-root; API/worker root filesystems are read-only; worker drops Linux capabilities and has CPU/RAM limits.

## Requirements

- Ubuntu 22.04 host (Docker containers include their own userspace).
- Docker Engine and Docker Compose plugin.
- Internet access while building images (DIE Debian package and signature database are fetched from the official project).

The scanner image uses the official Ubuntu 24.04 (`noble`) DIE package. This is independent of the host OS version and avoids trying to install a Noble package directly on Jammy.

## 1. Install Docker on Ubuntu 22.04

If Docker is already installed, skip this step.

```bash
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run --rm hello-world
```

## 2. Configure secrets

```bash
cp .env.example .env
```

Generate secure secrets:

```bash
openssl rand -hex 32
```

Use separate random values for `POSTGRES_PASSWORD`, `JWT_SECRET`, and `ADMIN_PASSWORD` in `.env`. The admin password should be at least 12 characters. Do not commit `.env` to Git.

## 3. Build and start

```bash
docker compose build --pull
docker compose up -d
```

Check status and logs:

```bash
docker compose ps
docker compose logs -f api worker
```

Open:

```text
http://SERVER_IP:8080
```

Sign in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env`.

> The first image build downloads the DIE package and current signature database. The build can take several minutes depending on network speed.

## 4. Verify DIE inside the API/worker image

```bash
docker compose exec api diec --help
docker compose exec worker diec --help
```

The worker calls:

```bash
diec -b -j /data/uploads/<generated-id>.sample
```

The JSON response is stored in PostgreSQL. If a DIE build emits non-JSON output, the application preserves it as a text result instead of discarding it.

## 5. Create an analyst user

Use an admin token:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=admin" \
  --data-urlencode "password=YOUR_ADMIN_PASSWORD" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -X POST http://127.0.0.1:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","email":"analyst1@example.local","password":"ChangeThisPassword123!","role":"analyst"}'
```

Only administrators can create/list users. There is no public registration endpoint.

## 6. API endpoints

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | Public | Login; returns JWT |
| GET | `/api/auth/me` | Authenticated | Current user |
| POST | `/api/scans` | Authenticated | Multi-file upload |
| GET | `/api/scans` | Authenticated | History/search |
| GET | `/api/scans/{id}` | Owner/admin | Report details |
| DELETE | `/api/scans/{id}` | Owner/admin | Delete scan/sample |
| GET | `/api/users` | Admin | List users |
| POST | `/api/users` | Admin | Create user |
| GET | `/api/health` | Internal | API health |

Swagger docs (internal API): `http://SERVER_IP:8080/api/docs`

## 7. Useful operations

```bash
# Status
docker compose ps

# Logs
docker compose logs -f --tail=200 api worker

# Restart application
docker compose restart api worker web

# Stop services (data volumes are preserved)
docker compose down

# Stop and DELETE all data (database, samples, redis queue) — destructive
docker compose down -v
```

## Security notes before exposing publicly

This is a starter deployment, not a complete malware-analysis sandbox.

1. Put Nginx behind a TLS reverse proxy or configure HTTPS before Internet exposure.
2. Restrict inbound access with a firewall/VPN; do not expose PostgreSQL or Redis.
3. Uploaded samples are untrusted. DIE parses them; a parser vulnerability could compromise the worker. For higher assurance, run each scan in a disposable, network-disabled sandbox container/VM with strict seccomp/AppArmor, CPU, memory, PID, file-size and wall-clock limits.
4. The worker has no Linux capabilities, runs as a non-root user, has a read-only root filesystem and no network route to the outside. Docker's internal network is used for service communication.
5. The current deployment retains uploaded samples until an administrator/user deletes the scan. Define a retention policy and backups.
6. Set `MAX_UPLOAD_MB` and `MAX_SCAN_SECONDS` to suit your server. The UI currently displays 250 MB as the default upload limit; change the text in `frontend/src/App.jsx` if you customize it.
7. Consider adding audit logs, password reset, rate limiting, CSRF policy for cookie-based auth, and per-user quotas before production use.

## Notes / troubleshooting

- If the build fails downloading the DIE package, check the release version and architecture. The supplied build argument defaults to `DIE_VERSION=4.1.0` and the package URL uses the official `noble_amd64.deb`.
- If the signature database is not populated, inspect the image build logs and verify the upstream `Detect-It-Easy` repository still contains its `db/` directory.
- If `diec` exits non-zero, inspect `docker compose logs worker`. The raw CLI output and error are stored in the scan record.
- For production, pin the DIE package version and signature database to a reviewed commit rather than tracking the latest database.
