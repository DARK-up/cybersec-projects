# DARK Enterprise Deployment Guide

## 1. Local Bare-Metal / Development
```bash
cd dark
pip install -r requirements.txt
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

## 2. Hardened Docker Container (Non-Root `darkuser`)
```bash
docker build -t dark-enterprise:3.0 .
docker run -d --name dark-api -p 8000:8000 \
  -e DARK_MASTER_KEY="$(openssl rand -hex 32)" \
  -e DARK_MAX_PARALLEL=16 \
  dark-enterprise:3.0
```

## 3. Distributed PostgreSQL + Redis + Celery Compose Stack
```bash
docker compose up -d
```
- **API Controller**: `:8000`
- **PostgreSQL 16**: `DARK_DB_URL=postgresql://dark:...@postgres:5432/dark`
- **Redis + Celery Workers**: horizontal scan execution (`dark/celery_worker.py`)

## 4. Environment Variables
| Variable | Purpose | Default |
|---|---|---|
| `DARK_DB_URL` | SQLite path or PostgreSQL DSN (`postgresql://...`) | `sqlite:///dark/dark_enterprise.db` |
| `DARK_MASTER_KEY` | Vault & TOTP secret encryption key | Auto-generated in `dark/.dark_master_key` |
| `DARK_MAX_PARALLEL` | Concurrent in-process scan worker cap | `16` |
| `DARK_LOG_FORMAT` | `json` for structured JSON logs | `json` |
