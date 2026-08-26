#!/usr/bin/env python3
"""
VibeGuard Phase 5 — Test repository setup script.

Creates the vibeguard-test-app GitHub repository with base code on main
and 30 test branches covering Safe, Authorization, Secret, Authentication,
and Injection scenarios.

Usage:
    python evaluation/setup_test_repo.py \\
        --repo <owner/repo-name> \\
        --token <github-pat> \\
        [--create]   # create the repo via API if it does not exist

The script:
  1. Creates (or uses existing) the GitHub repo.
  2. Clones it into a temp directory.
  3. Pushes the base FastAPI app to main.
  4. Creates and pushes all 30 test branches.

Requirements: git in PATH, Python 3.10+
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
APP_DIR = SCRIPT_DIR / "app"

# ---------------------------------------------------------------------------
# Branch change definitions
# Each key is a branch name.  Each value is a dict {filepath: content}.
# Filepaths are relative to the repo root.
# ---------------------------------------------------------------------------

# ── Reusable base file content snippets ────────────────────────────────────

_BASE_ADMIN = """\
from fastapi import APIRouter, Depends

from backend.auth.dependencies import require_admin

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/dashboard")
def get_dashboard(user=Depends(require_admin)):
    return {"message": "Admin Dashboard"}


@router.get("/users")
def list_users(user=Depends(require_admin)):
    return {"users": []}


@router.delete("/users/{user_id}")
def delete_user_admin(user_id: int, user=Depends(require_admin)):
    return {"deleted": user_id}


@router.get("/settings")
def get_settings(user=Depends(require_admin)):
    return {"settings": {}}


@router.put("/settings")
def update_settings(settings: dict, user=Depends(require_admin)):
    return {"updated": True}


@router.get("/logs")
def get_logs(user=Depends(require_admin)):
    return {"logs": []}


@router.post("/announcements")
def create_announcement(data: dict, user=Depends(require_admin)):
    return {"created": True}


@router.delete("/announcements/{announcement_id}")
def delete_announcement(announcement_id: int, user=Depends(require_admin)):
    return {"deleted": announcement_id}
"""

_BASE_CONFIG = """\
import os

APP_NAME = "vibeguard-test-app"
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
"""

_BASE_DEPS = """\
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from backend.auth.jwt_handler import verify_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
"""

_BASE_JWT = """\
import os
from datetime import datetime, timedelta

import jwt

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
ALGORITHM = "HS256"


def create_token(data: dict, expires_minutes: int = 30) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
"""

BRANCH_CHANGES: dict[str, dict[str, str]] = {

    # ── Safe PRs ────────────────────────────────────────────────────────────

    "safe/readme-update": {
        "README.md": textwrap.dedent("""\
            # vibeguard-test-app

            VibeGuard 평가용 FastAPI 테스트 애플리케이션.

            ## Recent Updates

            - Health check endpoints added
            - Admin dashboard improved
            - Logging enhanced

            ## 구조

            - `backend/auth/` — JWT 인증 + 권한 의존성
            - `backend/routes/admin.py` — 관리자 전용 엔드포인트
            - `backend/routes/users.py` — 사용자 프로필

            ## 실행

            ```bash
            pip install fastapi uvicorn python-jose
            uvicorn backend.main:app --reload
            ```
        """),
    },

    "safe/test-addition": {
        "tests/test_auth.py": textwrap.dedent("""\
            import pytest
            from fastapi.testclient import TestClient
            from backend.main import app

            client = TestClient(app)


            def test_admin_dashboard_unauthorized():
                response = client.get("/admin/dashboard")
                assert response.status_code == 401


            def test_admin_users_unauthorized():
                response = client.get("/admin/users")
                assert response.status_code == 401


            def test_admin_logs_unauthorized():
                response = client.get("/admin/logs")
                assert response.status_code == 401


            def test_products_unauthorized():
                response = client.get("/products/")
                assert response.status_code == 401


            def test_users_me_unauthorized():
                response = client.get("/users/me")
                assert response.status_code == 401
        """),
    },

    "safe/public-endpoint": {
        "backend/routes/public.py": textwrap.dedent("""\
            from fastapi import APIRouter

            router = APIRouter(prefix="/public", tags=["public"])


            @router.get("/")
            def public_index():
                return {"message": "Welcome to vibeguard-test-app"}


            @router.get("/status")
            def public_status():
                return {"status": "ok"}


            @router.get("/info")
            def public_info():
                return {
                    "name": "vibeguard-test-app",
                    "version": "1.0.0",
                    "docs": "/docs",
                }
        """),
    },

    "safe/admin-with-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/reports")
            def get_reports(user=Depends(require_admin)):
                return {"reports": [], "generated_by": user.get("sub")}
        """),
    },

    "safe/user-endpoint": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}


            @router.get("/profile")
            def get_profile(user=Depends(get_current_user)):
                return {"profile": {"sub": user.get("sub"), "role": user.get("role")}}
        """),
    },

    "safe/docs-update": {
        "docs/API.md": textwrap.dedent("""\
            # vibeguard-test-app API

            ## Authentication

            All protected endpoints require a Bearer JWT token.

            ```
            Authorization: Bearer <token>
            ```

            ## Rate Limiting

            API calls are rate-limited to 100 requests per minute per token.

            ## Endpoints

            ### Public
            - `GET /health` — Health check
            - `GET /public/` — Welcome message
            - `GET /public/status` — Status
            - `GET /public/info` — App info

            ### Users (requires user auth)
            - `GET /users/me` — My profile
            - `PUT /users/me` — Update profile
            - `GET /users/me/orders` — My orders

            ### Admin (requires admin role)
            - `GET /admin/dashboard` — Dashboard
            - `GET /admin/users` — List users
            - `DELETE /admin/users/{id}` — Delete user
            - `GET /admin/settings` — Settings
            - `PUT /admin/settings` — Update settings
            - `GET /admin/logs` — Audit logs
            - `POST /admin/announcements` — Create announcement
            - `DELETE /admin/announcements/{id}` — Delete announcement
            - `GET /admin/reports` — Reports

            ### Products (requires admin role)
            - `GET /products/` — List products
            - `POST /products/` — Create product
            - `PUT /products/{id}` — Update product
            - `DELETE /products/{id}` — Delete product
        """),
    },

    "safe/refactor-logic": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            def _format_user(user_id: int) -> dict:
                return {"id": user_id, "status": "active"}


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {
                    "message": "Admin Dashboard",
                    "admin": user.get("sub"),
                    "stats": {"users": 0, "orders": 0},
                }


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": [], "total": 0, "page": 1}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id, "deleted_by": user.get("sub")}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}, "last_updated": None}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True, "keys_changed": list(settings.keys())}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": [], "total": 0}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True, "created_by": user.get("sub")}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}
        """),
    },

    "safe/custom-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            async def verify_and_require_admin(user=Depends(require_admin)):
                \"\"\"Additional admin verification layer.\"\"\"
                if not user.get("sub"):
                    from fastapi import HTTPException, status
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
                return user


            @router.get("/export")
            async def export_data(user=Depends(verify_and_require_admin)):
                return {"export": "data", "requested_by": user.get("sub")}
        """),
    },

    "safe/config-safe": {
        "backend/config.py": textwrap.dedent("""\
            import os

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
            REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
            ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
            MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "10"))
        """),
    },

    "safe/migration": {
        "migrations/0001_initial.sql": textwrap.dedent("""\
            -- Initial schema migration
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                description TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """),
    },

    # ── Authorization Regression PRs ────────────────────────────────────────

    "vuln/admin-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.delete("/users")
            def delete_all_users():
                # TODO: add authentication
                return {"deleted": "all"}
        """),
    },

    "vuln/admin-wrong-level": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user, require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}


            @router.delete("/settings/reset")
            def reset_settings(user=Depends(get_current_user)):
                return {"reset": True}
        """),
    },

    "vuln/admin-get-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/stats")
            def get_stats():
                return {"total_users": 0, "total_orders": 0, "revenue": 0}
        """),
    },

    "vuln/admin-post-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/bulk-delete")
            def bulk_delete_users(data: dict):
                user_ids = data.get("ids", [])
                return {"deleted": user_ids, "count": len(user_ids)}
        """),
    },

    "vuln/remove-auth": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard():
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}
        """),
    },

    "vuln/internal-no-auth": {
        "backend/routes/internal.py": textwrap.dedent("""\
            from fastapi import APIRouter

            router = APIRouter(prefix="/internal", tags=["internal"])


            @router.get("/config")
            def get_internal_config():
                return {
                    "database_url": "postgresql://prod-db:5432/app",
                    "redis_url": "redis://prod-redis:6379",
                    "feature_flags": {"new_ui": True, "beta_api": False},
                }


            @router.get("/metrics")
            def get_internal_metrics():
                return {"requests_per_second": 42, "error_rate": 0.01}
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes import internal

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(internal.router)
        """),
    },

    "vuln/admin-multiple": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/audit-log")
            def get_audit_log():
                return {"logs": [], "total": 0}


            @router.delete("/audit-log")
            def clear_audit_log():
                return {"cleared": True}


            @router.post("/impersonate")
            def impersonate_user(data: dict):
                user_id = data.get("user_id")
                return {"token": f"impersonation_token_for_{user_id}"}
        """),
    },

    "vuln/middleware-remove": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard():
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users():
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings():
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict):
                return {"updated": True}


            @router.get("/logs")
            def get_logs():
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int):
                return {"deleted": announcement_id}
        """),
    },

    "vuln/partial-auth": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}


            @router.get("/inventory")
            def get_inventory():
                return {"items": []}


            @router.post("/inventory")
            def create_inventory_item(data: dict):
                return {"created": True}


            @router.put("/inventory/{item_id}")
            def update_inventory_item(item_id: int, data: dict, user=Depends(require_admin)):
                return {"updated": item_id}


            @router.delete("/inventory/{item_id}")
            def delete_inventory_item(item_id: int, user=Depends(require_admin)):
                return {"deleted": item_id}
        """),
    },

    "vuln/decorator-missing": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            # @require_admin — 관리자만 접근 가능
            @router.get("/sensitive-data")
            def get_sensitive_data():
                return {"data": "sensitive admin information"}
        """),
    },

    # ── Secret Exposure PRs ─────────────────────────────────────────────────

    "vuln/hardcoded-key": {
        "backend/config.py": textwrap.dedent("""\
            import os

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

            OPENAI_API_KEY = "sk-abc123XYZsecretKeyDoNotShare9876543210abcdef"
            STRIPE_API_KEY = "sk_live_51HabcDEfghIJklMNopqRSTUvwxyz"
        """),
    },

    "vuln/jwt-secret": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = "mysecret_supersimple_donotuse"
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "vuln/db-password": {
        "backend/config.py": textwrap.dedent("""\
            import os

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

            DB_HOST = "prod-postgres.internal"
            DB_PORT = 5432
            DB_NAME = "appdb"
            DB_USER = "appuser"
            DB_PASSWORD = "admin123"
            DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        """),
    },

    "vuln/env-in-code": {
        "backend/config.py": textwrap.dedent("""\
            import os

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

            AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
            AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            AWS_DEFAULT_REGION = "us-east-1"
        """),
    },

    "vuln/token-in-comment": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # GitHub integration
            # token: ghp_xK9mN2pQ8rT5vW3yZ1aB4cD6eF7gH0iJ
            GITHUB_REPO = os.environ.get("GITHUB_REPO", "")
        """),
    },

    # ── Authentication Regression PRs ───────────────────────────────────────

    "vuln/no-login-check": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends, Request

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}


            @router.get("/user-data/{user_id}")
            def get_user_data(user_id: int, request: Request):
                # Retrieve user data — authentication check omitted
                return {"user_id": user_id, "data": {"email": "user@example.com", "orders": []}}
        """),
    },

    "vuln/token-verify-skip": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    # payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    # return payload
                    import base64, json as _json
                    parts = token.split(".")
                    if len(parts) == 3:
                        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        return _json.loads(base64.urlsafe_b64decode(padded))
                    return None
                except Exception:
                    return None
        """),
    },

    "vuln/session-bypass": {
        "backend/auth/dependencies.py": textwrap.dedent("""\
            from fastapi import Depends, HTTPException, Request, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

            BYPASS_USERS = ["debug_user", "test_admin"]


            async def get_current_user(token: str = Depends(oauth2_scheme)):
                payload = verify_token(token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def require_admin(user=Depends(get_current_user)):
                if user.get("role") != "admin":
                    if user.get("sub") in BYPASS_USERS:
                        return user
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    # ── Injection PRs ────────────────────────────────────────────────────────

    "vuln/sql-injection": {
        "backend/routes/users.py": textwrap.dedent("""\
            import sqlite3

            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}


            @router.get("/search")
            def search_users(q: str, user=Depends(get_current_user)):
                conn = sqlite3.connect("app.db")
                cursor = conn.cursor()
                query = f"SELECT * FROM users WHERE name LIKE '%{q}%'"
                cursor.execute(query)
                results = cursor.fetchall()
                conn.close()
                return {"results": results}
        """),
    },

    "vuln/command-injection": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/ping")
            def ping_host(data: dict, user=Depends(require_admin)):
                import subprocess
                host = data.get("host", "localhost")
                result = subprocess.call(f"ping -c 1 {host}", shell=True)
                return {"exit_code": result}
        """),
    },

    # ── Safe PRs (S11-S30) ──────────────────────────────────────────────────

    "safe/auth-refactor": {
        "backend/auth/dependencies.py": textwrap.dedent("""\
            \"\"\"
            Authentication dependencies for FastAPI endpoints.

            Provides get_current_user and require_admin dependency functions
            for use with FastAPI's Depends() injection system.
            \"\"\"
            from fastapi import Depends, HTTPException, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


            def _extract_token_payload(token: str) -> dict:
                \"\"\"Decode and validate a Bearer token, returning its payload.\"\"\"
                payload = verify_token(token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
                \"\"\"Resolve the authenticated user from the Bearer token.\"\"\"
                return _extract_token_payload(token)


            async def require_admin(user: dict = Depends(get_current_user)) -> dict:
                \"\"\"Require that the authenticated user has the 'admin' role.\"\"\"
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "safe/jwt-rename": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def validate_jwt_token(token: str) -> dict | None:
                \"\"\"Decode and verify a JWT token. Returns payload or None on failure.\"\"\"
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None


            # Backward-compatible alias
            verify_token = validate_jwt_token
        """),
        "backend/auth/dependencies.py": textwrap.dedent("""\
            from fastapi import Depends, HTTPException, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import validate_jwt_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


            async def get_current_user(token: str = Depends(oauth2_scheme)):
                payload = validate_jwt_token(token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def require_admin(user=Depends(get_current_user)):
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "safe/env-example": {
        ".env.example": textwrap.dedent("""\
            # Copy this file to .env and fill in real values.
            # NEVER commit .env to version control.

            # JWT
            JWT_SECRET_KEY=your-secret-here-change-before-production

            # Database
            DATABASE_URL=postgresql://user:password@localhost/dbname

            # Application
            DEBUG=false
            ACCESS_TOKEN_EXPIRE_MINUTES=30
            ALLOWED_ORIGINS=http://localhost:3000

            # External services (fill in with real values)
            SLACK_WEBHOOK_URL=https://hooks.slack.com/services/CHANGE/ME/change_me
            SENDGRID_API_KEY=SG.replace_with_real_key
            STRIPE_SECRET_KEY=sk_test_replace_with_real_key

            # Redis
            REDIS_URL=redis://localhost:6379/0
        """),
    },

    "safe/rate-limiting": {
        "backend/middleware.py": textwrap.dedent("""\
            import time
            from collections import defaultdict
            from typing import Callable

            from fastapi import Request, Response
            from starlette.middleware.base import BaseHTTPMiddleware


            class RateLimitMiddleware(BaseHTTPMiddleware):
                \"\"\"Simple in-memory sliding-window rate limiter.\"\"\"

                def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
                    super().__init__(app)
                    self.max_requests = max_requests
                    self.window_seconds = window_seconds
                    self._buckets: dict[str, list[float]] = defaultdict(list)

                def _get_client_id(self, request: Request) -> str:
                    forwarded = request.headers.get("X-Forwarded-For")
                    if forwarded:
                        return forwarded.split(",")[0].strip()
                    return request.client.host if request.client else "unknown"

                async def dispatch(self, request: Request, call_next: Callable) -> Response:
                    client_id = self._get_client_id(request)
                    now = time.monotonic()
                    window_start = now - self.window_seconds

                    hits = self._buckets[client_id]
                    # Prune old entries
                    self._buckets[client_id] = [t for t in hits if t > window_start]

                    if len(self._buckets[client_id]) >= self.max_requests:
                        return Response(
                            content='{"detail":"Rate limit exceeded"}',
                            status_code=429,
                            media_type="application/json",
                        )

                    self._buckets[client_id].append(now)
                    return await call_next(request)
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.middleware import RateLimitMiddleware
            from backend.routes import admin, health, products, public, users

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
        """),
    },

    "safe/cors-config": {
        "backend/main.py": textwrap.dedent("""\
            import os

            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware

            from backend.routes import admin, health, products, public, users

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            _raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000")
            allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

            app.add_middleware(
                CORSMiddleware,
                allow_origins=allowed_origins,
                allow_credentials=True,
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allow_headers=["Authorization", "Content-Type"],
            )

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
        """),
    },

    "safe/bcrypt-upgrade": {
        "backend/auth/password.py": textwrap.dedent("""\
            \"\"\"
            Password hashing utilities using bcrypt.

            Usage:
                hashed = hash_password("mysecretpassword")
                is_valid = verify_password("mysecretpassword", hashed)
            \"\"\"
            import bcrypt


            def hash_password(plain: str) -> str:
                \"\"\"Hash a plaintext password with bcrypt (auto-generates salt).\"\"\"
                salt = bcrypt.gensalt(rounds=12)
                return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


            def verify_password(plain: str, hashed: str) -> bool:
                \"\"\"Verify a plaintext password against a bcrypt hash.\"\"\"
                return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        """),
    },

    "safe/pagination": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends, Query

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(
                skip: int = Query(0, ge=0),
                limit: int = Query(20, ge=1, le=100),
                user=Depends(require_admin),
            ):
                return {"users": [], "skip": skip, "limit": limit, "total": 0}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(
                skip: int = Query(0, ge=0),
                limit: int = Query(50, ge=1, le=200),
                user=Depends(require_admin),
            ):
                return {"logs": [], "skip": skip, "limit": limit}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}
        """),
    },

    "safe/error-handler": {
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI, HTTPException, Request
            from fastapi.responses import JSONResponse

            from backend.routes import admin, health, products, public, users

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")


            @app.exception_handler(HTTPException)
            async def http_exception_handler(request: Request, exc: HTTPException):
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail, "status_code": exc.status_code},
                )


            @app.exception_handler(Exception)
            async def generic_exception_handler(request: Request, exc: Exception):
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error"},
                )


            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
        """),
    },

    "safe/response-models": {
        "backend/models/__init__.py": "",
        "backend/models/schemas.py": textwrap.dedent("""\
            from typing import Optional
            from pydantic import BaseModel


            class UserResponse(BaseModel):
                sub: str
                role: str
                email: Optional[str] = None


            class AdminUserResponse(BaseModel):
                sub: str
                role: str
                email: Optional[str] = None
                created_at: Optional[str] = None
                is_active: bool = True


            class AnnouncementCreate(BaseModel):
                title: str
                body: str


            class AnnouncementResponse(BaseModel):
                id: int
                title: str
                body: str
                created_by: Optional[str] = None


            class ProductResponse(BaseModel):
                id: int
                name: str
                price: float
                description: Optional[str] = None


            class SettingsResponse(BaseModel):
                debug: bool = False
                max_upload_size_mb: int = 10
                allowed_origins: list[str] = []
        """),
    },

    "safe/new-product-endpoint": {
        "backend/routes/products.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends, HTTPException, status

            from backend.auth.dependencies import get_current_user, require_admin

            router = APIRouter(prefix="/products", tags=["products"])

            # In-memory product store for demo purposes
            _PRODUCTS: dict[int, dict] = {
                1: {"id": 1, "name": "Widget A", "price": 9.99, "description": "Basic widget"},
                2: {"id": 2, "name": "Widget B", "price": 19.99, "description": "Premium widget"},
            }


            @router.get("/")
            def list_products(user=Depends(get_current_user)):
                return {"products": list(_PRODUCTS.values())}


            @router.get("/{product_id}")
            def get_product(product_id: int, user=Depends(get_current_user)):
                product = _PRODUCTS.get(product_id)
                if not product:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
                return product


            @router.post("/")
            def create_product(data: dict, user=Depends(require_admin)):
                new_id = max(_PRODUCTS.keys(), default=0) + 1
                product = {"id": new_id, **data}
                _PRODUCTS[new_id] = product
                return product


            @router.put("/{product_id}")
            def update_product(product_id: int, data: dict, user=Depends(require_admin)):
                if product_id not in _PRODUCTS:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
                _PRODUCTS[product_id].update(data)
                return _PRODUCTS[product_id]


            @router.delete("/{product_id}")
            def delete_product(product_id: int, user=Depends(require_admin)):
                if product_id not in _PRODUCTS:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
                del _PRODUCTS[product_id]
                return {"deleted": product_id}
        """),
    },

    "safe/health-extend": {
        "backend/routes/health.py": textwrap.dedent("""\
            import time
            from datetime import datetime, timezone

            from fastapi import APIRouter

            router = APIRouter(tags=["health"])

            _START_TIME = time.monotonic()


            def _check_db() -> dict:
                \"\"\"Attempt a lightweight DB connectivity check.\"\"\"
                try:
                    import sqlite3
                    conn = sqlite3.connect(":memory:")
                    conn.execute("SELECT 1")
                    conn.close()
                    return {"status": "ok"}
                except Exception as exc:
                    return {"status": "error", "detail": str(exc)}


            @router.get("/health")
            def health_check():
                uptime_seconds = round(time.monotonic() - _START_TIME, 2)
                return {
                    "status": "ok",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "uptime_seconds": uptime_seconds,
                    "components": {
                        "database": _check_db(),
                    },
                }
        """),
    },

    "safe/logging-setup": {
        "backend/logging_config.py": textwrap.dedent("""\
            \"\"\"
            Structured JSON logging configuration.

            Call configure_logging() once at application startup.
            \"\"\"
            import logging
            import sys
            import json
            from datetime import datetime, timezone


            class JsonFormatter(logging.Formatter):
                \"\"\"Emit log records as single-line JSON objects.\"\"\"

                def format(self, record: logging.LogRecord) -> str:
                    log_object = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "level": record.levelname,
                        "logger": record.name,
                        "message": record.getMessage(),
                        "module": record.module,
                        "function": record.funcName,
                        "line": record.lineno,
                    }
                    if record.exc_info:
                        log_object["exception"] = self.formatException(record.exc_info)
                    return json.dumps(log_object, ensure_ascii=False)


            def configure_logging(level: str = "INFO") -> None:
                \"\"\"Configure root logger to emit structured JSON to stdout.\"\"\"
                handler = logging.StreamHandler(sys.stdout)
                handler.setFormatter(JsonFormatter())

                root = logging.getLogger()
                root.setLevel(getattr(logging, level.upper(), logging.INFO))
                root.handlers = [handler]

                # Suppress noisy third-party loggers
                logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        """),
    },

    "safe/requirements-update": {
        "requirements.txt": textwrap.dedent("""\
            fastapi>=0.104.0
            uvicorn[standard]>=0.24.0
            python-jose[cryptography]>=3.3.0
            passlib[bcrypt]>=1.7.4
            cryptography>=41.0.0
            pydantic>=2.4.0
            python-multipart>=0.0.6
            httpx>=0.25.0
        """),
    },

    "safe/admin-audit": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/audit-events")
            def list_audit_events(
                skip: int = 0,
                limit: int = 50,
                user=Depends(require_admin),
            ):
                \"\"\"Return paginated audit event log (admin only).\"\"\"
                return {
                    "events": [],
                    "skip": skip,
                    "limit": limit,
                    "total": 0,
                    "requested_by": user.get("sub"),
                }
        """),
    },

    "safe/security-headers": {
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI, Request
            from fastapi.responses import Response
            from starlette.middleware.base import BaseHTTPMiddleware

            from backend.routes import admin, health, products, public, users


            class SecurityHeadersMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request: Request, call_next):
                    response: Response = await call_next(request)
                    response.headers["X-Content-Type-Options"] = "nosniff"
                    response.headers["X-Frame-Options"] = "DENY"
                    response.headers["X-XSS-Protection"] = "1; mode=block"
                    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                    response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
                    return response


            app = FastAPI(title="vibeguard-test-app", version="1.0.0")
            app.add_middleware(SecurityHeadersMiddleware)

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
        """),
    },

    "safe/api-versioning": {
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users

            app = FastAPI(
                title="vibeguard-test-app",
                version="2.0.0",
                docs_url="/api/v1/docs",
                openapi_url="/api/v1/openapi.json",
            )

            app.include_router(health.router, prefix="/api/v1")
            app.include_router(public.router, prefix="/api/v1")
            app.include_router(users.router, prefix="/api/v1")
            app.include_router(admin.router, prefix="/api/v1")
            app.include_router(products.router, prefix="/api/v1")
        """),
    },

    "safe/input-validation": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from typing import Optional
            from fastapi import APIRouter, Depends
            from pydantic import BaseModel, Field

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            class AnnouncementCreate(BaseModel):
                title: str = Field(..., min_length=1, max_length=200)
                body: str = Field(..., min_length=1, max_length=5000)
                pinned: Optional[bool] = False


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: AnnouncementCreate, user=Depends(require_admin)):
                return {"created": True, "title": data.title, "created_by": user.get("sub")}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}
        """),
    },

    "safe/password-policy": {
        "backend/auth/password_policy.py": textwrap.dedent("""\
            \"\"\"Password strength policy enforcement.\"\"\"
            import re
            from dataclasses import dataclass, field


            @dataclass
            class PolicyViolation:
                rule: str
                message: str


            @dataclass
            class PolicyResult:
                valid: bool
                violations: list[PolicyViolation] = field(default_factory=list)

                @property
                def messages(self) -> list[str]:
                    return [v.message for v in self.violations]


            def check_password_strength(password: str) -> PolicyResult:
                \"\"\"
                Evaluate password against the application's strength policy.

                Rules:
                  - Minimum 8 characters
                  - At least one uppercase letter
                  - At least one lowercase letter
                  - At least one digit
                  - At least one special character
                \"\"\"
                violations: list[PolicyViolation] = []

                if len(password) < 8:
                    violations.append(PolicyViolation("min_length", "Password must be at least 8 characters"))
                if not re.search(r"[A-Z]", password):
                    violations.append(PolicyViolation("uppercase", "Password must contain an uppercase letter"))
                if not re.search(r"[a-z]", password):
                    violations.append(PolicyViolation("lowercase", "Password must contain a lowercase letter"))
                if not re.search(r"\\d", password):
                    violations.append(PolicyViolation("digit", "Password must contain a digit"))
                if not re.search(r"[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]", password):
                    violations.append(PolicyViolation("special", "Password must contain a special character"))

                return PolicyResult(valid=len(violations) == 0, violations=violations)
        """),
    },

    "safe/env-validation": {
        "backend/config.py": textwrap.dedent("""\
            import os
            import sys

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            DATABASE_URL = os.environ.get("DATABASE_URL", "")
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

            _REQUIRED_ENV_VARS = ["JWT_SECRET_KEY", "DATABASE_URL"]


            def validate_required_env_vars() -> None:
                \"\"\"Raise RuntimeError if any required env var is missing or empty.\"\"\"
                missing = [
                    var for var in _REQUIRED_ENV_VARS
                    if not os.environ.get(var, "").strip()
                ]
                if missing:
                    raise RuntimeError(
                        f"Missing required environment variables: {', '.join(missing)}. "
                        "Set them before starting the application."
                    )


            # Validate at import time so the app fails fast on misconfiguration
            if not DEBUG:
                validate_required_env_vars()
        """),
    },

    "safe/db-pool": {
        "backend/database.py": textwrap.dedent("""\
            \"\"\"
            SQLAlchemy engine and session factory.

            All connection parameters are sourced from environment variables.
            \"\"\"
            import os

            from sqlalchemy import create_engine, text
            from sqlalchemy.orm import sessionmaker, DeclarativeBase

            DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
            DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "5"))
            DB_MAX_OVERFLOW = int(os.environ.get("DB_MAX_OVERFLOW", "10"))
            DB_POOL_TIMEOUT = int(os.environ.get("DB_POOL_TIMEOUT", "30"))
            DB_POOL_RECYCLE = int(os.environ.get("DB_POOL_RECYCLE", "1800"))

            _connect_args = {}
            if DATABASE_URL.startswith("sqlite"):
                _connect_args["check_same_thread"] = False

            engine = create_engine(
                DATABASE_URL,
                pool_size=DB_POOL_SIZE,
                max_overflow=DB_MAX_OVERFLOW,
                pool_timeout=DB_POOL_TIMEOUT,
                pool_recycle=DB_POOL_RECYCLE,
                connect_args=_connect_args,
            )

            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


            class Base(DeclarativeBase):
                pass


            def get_db():
                \"\"\"FastAPI dependency that yields a DB session.\"\"\"
                db = SessionLocal()
                try:
                    yield db
                finally:
                    db.close()
        """),
    },

    # ── Authorization Regression PRs (A11-A25) ──────────────────────────────

    "vuln/idor-user-data": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends, HTTPException, status

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}


            @router.get("/{user_id}/profile")
            def get_user_profile(user_id: int, user=Depends(get_current_user)):
                # Missing ownership check: user_id should be verified against current user
                return {
                    "user_id": user_id,
                    "email": f"user{user_id}@example.com",
                    "full_name": f"User {user_id}",
                    "phone": "+1-555-0100",
                    "address": "123 Main St",
                }
        """),
    },

    "vuln/privilege-downgrade": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user, require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}


            @router.delete("/users/bulk")
            def bulk_delete_users(data: dict, user=Depends(get_current_user)):
                user_ids = data.get("ids", [])
                # Should require require_admin, not just get_current_user
                return {"deleted": user_ids, "count": len(user_ids)}
        """),
    },

    "vuln/product-delete-no-auth": {
        "backend/routes/products.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user, require_admin

            router = APIRouter(prefix="/products", tags=["products"])


            @router.get("/")
            def list_products(user=Depends(get_current_user)):
                return {"products": []}


            @router.post("/")
            def create_product(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.put("/{product_id}")
            def update_product(product_id: int, data: dict, user=Depends(require_admin)):
                return {"updated": product_id}


            @router.delete("/{product_id}")
            def delete_product(product_id: int):
                # Authentication missing — any unauthenticated user can delete
                return {"deleted": product_id}
        """),
    },

    "vuln/user-role-change": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.put("/me/role")
            def update_my_role(data: dict, user=Depends(get_current_user)):
                # Privilege escalation: any authenticated user can change their own role
                new_role = data.get("role")
                return {"sub": user.get("sub"), "role": new_role, "updated": True}
        """),
    },

    "vuln/debug-endpoint": {
        "backend/routes/debug.py": textwrap.dedent("""\
            import os

            from fastapi import APIRouter

            router = APIRouter(prefix="/debug", tags=["debug"])


            @router.get("/config")
            def get_debug_config():
                \"\"\"Exposes runtime configuration — no authentication required.\"\"\"
                return {
                    "database_url": os.environ.get("DATABASE_URL", ""),
                    "jwt_secret_key": os.environ.get("JWT_SECRET_KEY", ""),
                    "redis_url": os.environ.get("REDIS_URL", ""),
                    "debug": os.environ.get("DEBUG", "false"),
                    "allowed_origins": os.environ.get("ALLOWED_ORIGINS", ""),
                }


            @router.get("/env")
            def get_all_env():
                \"\"\"Dump all environment variables — no authentication required.\"\"\"
                return {"env": dict(os.environ)}
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes import debug

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(debug.router)
        """),
    },

    "vuln/batch-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/batch-create")
            def batch_create_users(data: dict):
                users_data = data.get("users", [])
                created_ids = list(range(1, len(users_data) + 1))
                return {"created": created_ids, "count": len(created_ids)}
        """),
    },

    "vuln/report-wrong-level": {
        "backend/routes/admin.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user, require_admin

            router = APIRouter(prefix="/admin", tags=["admin"])


            @router.get("/dashboard")
            def get_dashboard(user=Depends(require_admin)):
                return {"message": "Admin Dashboard"}


            @router.get("/users")
            def list_users(user=Depends(require_admin)):
                return {"users": []}


            @router.delete("/users/{user_id}")
            def delete_user_admin(user_id: int, user=Depends(require_admin)):
                return {"deleted": user_id}


            @router.get("/settings")
            def get_settings(user=Depends(require_admin)):
                return {"settings": {}}


            @router.put("/settings")
            def update_settings(settings: dict, user=Depends(require_admin)):
                return {"updated": True}


            @router.get("/logs")
            def get_logs(user=Depends(require_admin)):
                return {"logs": []}


            @router.post("/announcements")
            def create_announcement(data: dict, user=Depends(require_admin)):
                return {"created": True}


            @router.delete("/announcements/{announcement_id}")
            def delete_announcement(announcement_id: int, user=Depends(require_admin)):
                return {"deleted": announcement_id}


            @router.get("/financial-report")
            def get_financial_report(user=Depends(get_current_user)):
                # Should require require_admin — financial data is admin-only
                return {
                    "revenue": 125000.00,
                    "expenses": 42000.00,
                    "net_profit": 83000.00,
                    "transactions": [],
                }
        """),
    },

    "vuln/export-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/export/users")
            def export_all_users():
                return {
                    "users": [
                        {"id": 1, "sub": "user1", "email": "user1@example.com", "role": "user"},
                        {"id": 2, "sub": "admin1", "email": "admin@example.com", "role": "admin"},
                    ],
                    "exported_at": "2024-01-01T00:00:00Z",
                    "total": 2,
                }
        """),
    },

    "vuln/webhook-no-auth": {
        "backend/routes/webhooks.py": textwrap.dedent("""\
            from fastapi import APIRouter, Request

            router = APIRouter(prefix="/webhooks", tags=["webhooks"])


            @router.post("/payment-notify")
            async def payment_notify(request: Request):
                \"\"\"Process incoming payment notification — no signature verification.\"\"\"
                body = await request.json()
                payment_id = body.get("payment_id")
                amount = body.get("amount")
                status = body.get("status")
                # Process payment without verifying webhook signature
                return {"received": True, "payment_id": payment_id, "status": status}
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users, webhooks

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(webhooks.router)
        """),
    },

    "vuln/mass-assignment": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.post("/register")
            def register_user(data: dict):
                # Mass assignment: caller can pass role=admin and it will be stored
                user_record = {
                    "sub": data.get("username"),
                    "email": data.get("email"),
                    "role": data.get("role", "user"),  # User-supplied role field
                    **data,
                }
                return {"registered": True, "user": user_record}
        """),
    },

    "vuln/internal-api-no-auth": {
        "backend/routes/internal.py": textwrap.dedent("""\
            from fastapi import APIRouter

            router = APIRouter(prefix="/internal", tags=["internal"])


            @router.get("/users")
            def list_all_users():
                \"\"\"Return full user list including hashed passwords — no authentication.\"\"\"
                return {
                    "users": [
                        {
                            "id": 1,
                            "sub": "alice",
                            "email": "alice@example.com",
                            "hashed_password": "$2b$12$exampleHashedPasswordStringHere",
                            "role": "admin",
                        },
                        {
                            "id": 2,
                            "sub": "bob",
                            "email": "bob@example.com",
                            "hashed_password": "$2b$12$anotherExampleHashValue",
                            "role": "user",
                        },
                    ]
                }


            @router.get("/tokens")
            def list_active_tokens():
                \"\"\"Return active session tokens — no authentication.\"\"\"
                return {"tokens": []}
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes import internal

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(internal.router)
        """),
    },

    "vuln/file-serve-no-auth": {
        "backend/routes/files.py": textwrap.dedent("""\
            from fastapi import APIRouter
            from fastapi.responses import PlainTextResponse

            router = APIRouter(prefix="/files", tags=["files"])


            @router.get("/{filename}", response_class=PlainTextResponse)
            def serve_file(filename: str):
                \"\"\"Serve a file from the data directory — no authentication required.\"\"\"
                try:
                    with open(f"data/{filename}", "r", encoding="utf-8") as f:
                        return f.read()
                except FileNotFoundError:
                    return "File not found"
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes import files

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(files.router)
        """),
    },

    "vuln/admin-search-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/search")
            def search_resources(q: str = ""):
                # Missing authentication — any caller can search admin data
                return {
                    "query": q,
                    "users": [{"id": 1, "sub": "alice", "email": "alice@example.com"}],
                    "orders": [{"id": 1001, "user": "alice", "total": 99.99}],
                }
        """),
    },

    "vuln/user-delete-no-auth": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.delete("/{user_id}")
            def delete_user(user_id: int, current_user=Depends(get_current_user)):
                # Should require admin — any authenticated user can delete any account
                return {"deleted": user_id, "deleted_by": current_user.get("sub")}
        """),
    },

    "vuln/nested-resource-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/reports/{report_id}/details")
            def get_report_details(report_id: int):
                # Missing authentication on nested admin resource
                return {
                    "report_id": report_id,
                    "title": f"Report #{report_id}",
                    "data": {"revenue": 50000, "users_affected": 150},
                    "generated_at": "2024-01-01T00:00:00Z",
                }
        """),
    },

    # ── Secret Exposure PRs (E6-E15) ────────────────────────────────────────

    "vuln/env-fallback-secret": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "super-secret-fallback-key-2024")
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "vuln/slack-webhook": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Slack integration
            SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T01ABC123/B02DEF456/abcdefghijklmnopqrstuvwx"
            SLACK_CHANNEL = "#alerts"
        """),
    },

    "vuln/sendgrid-key": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Email service
            SENDGRID_API_KEY = "SG.xK9mN2pQ8rT5vW3yZ1aB4cD.6eF7gH0iJkL3mN4oP5qR6sT7uV8wX9yZ"
            SENDGRID_FROM_EMAIL = "noreply@example.com"
        """),
    },

    "vuln/multiple-secrets": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # GitHub OAuth
            GITHUB_CLIENT_ID = "Iv1.abcdef1234567890"
            GITHUB_CLIENT_SECRET = "abcdef1234567890abcdef1234567890abcdef12"

            # Twitter API
            TWITTER_API_KEY = "xK9mN2pQ8rT5vW3y"
            TWITTER_API_SECRET = "Z1aB4cD6eF7gH0iJkL3mN4oP5qR6sT7uV8wX9yZabcd1234"

            # Discord bot
            DISCORD_BOT_TOKEN = "MTA0NTY3ODkwMTIzNDU2Nzg5.GabCDE.xyz123abcDEFghiJKLmnoPQRstu"
        """),
    },

    "vuln/stripe-secret": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Payment processing
            STRIPE_SECRET_KEY = "sk_live_51HabcdefGHIjklmnOPqrstUVwxyz123456789"
            STRIPE_WEBHOOK_SECRET = "whsec_abcdefghijklmnopqrstuvwxyz123456"
            STRIPE_PUBLISHABLE_KEY = "pk_live_51HabcdefGHIjklmnopqrstuvwxyz"
        """),
    },

    "vuln/private-key-inline": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            ALGORITHM = "RS256"

            # RSA private key — should be loaded from secrets manager, not hardcoded
            PRIVATE_KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29oNBEDwCCSYoL
            VTDsXCTDFCBSBrJHmBBGnFOxnUPLuBkLKzMQjNlH5BZuQwAFpxMJlNBiN6y4V3x
            KJ1sXYfWMEJNwGPElCdNKpwOe5f/EXAMPLERSAPRIVATEKEYCONTENTHERE12345==
            -----END RSA PRIVATE KEY-----\"\"\"

            PUBLIC_KEY = \"\"\"-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzEXAMPLE==
            -----END PUBLIC KEY-----\"\"\"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "vuln/oauth-credentials": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Google OAuth2
            GOOGLE_CLIENT_ID = "123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"
            GOOGLE_CLIENT_SECRET = "GOCSPX-abcdefghijklmnopqrstuvwx"
            GOOGLE_REDIRECT_URI = "https://example.com/auth/google/callback"
        """),
    },

    "vuln/redis-password": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Cache / session storage
            REDIS_URL = "redis://:prodpassword123@redis-prod.internal:6379/0"
            REDIS_CACHE_URL = "redis://:cachepass456@redis-cache.internal:6379/1"
        """),
    },

    "vuln/twilio-credentials": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # SMS / voice
            TWILIO_ACCOUNT_SID = "AC0123456789abcdef0123456789abcdef"
            TWILIO_AUTH_TOKEN = "0123456789abcdef0123456789abcdef"
            TWILIO_PHONE_NUMBER = "+15550001234"
        """),
    },

    "vuln/cloud-multi-secret": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Azure Blob Storage
            AZURE_STORAGE_CONNECTION_STRING = (
                "DefaultEndpointsProtocol=https;AccountName=prodstorageacct;"
                "AccountKey=dGhpcyBpcyBhIGZha2UgYXp1cmUgc3RvcmFnZSBrZXkgZm9yIHRlc3Rpbmcgb25seSE=;"
                "EndpointSuffix=core.windows.net"
            )

            # GCP Service Account (fragment)
            GCP_SERVICE_ACCOUNT_KEY = (
                '{"type":"service_account","project_id":"my-prod-project",'
                '"private_key_id":"abc123def456","private_key":"-----BEGIN RSA PRIVATE KEY-----'
                '\\nMIIEowIBAAKCAQEAexamplekeycontenthere\\n-----END RSA PRIVATE KEY-----\\n",'
                '"client_email":"sa@my-prod-project.iam.gserviceaccount.com"}'
            )
        """),
    },

    # ── Authentication Regression PRs (T4-T10) ──────────────────────────────

    "vuln/jwt-no-expiry": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(
                        token,
                        SECRET_KEY,
                        algorithms=[ALGORITHM],
                        options={"verify_exp": False},  # Expiration check disabled
                    )
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "vuln/debug-bypass": {
        "backend/auth/dependencies.py": textwrap.dedent("""\
            import os

            from fastapi import Depends, HTTPException, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


            async def get_current_user(token: str = Depends(oauth2_scheme)):
                if os.environ.get("DEBUG") == "true":
                    # Debug bypass — skips all authentication when DEBUG=true
                    return {"sub": "admin", "role": "admin"}

                payload = verify_token(token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def require_admin(user=Depends(get_current_user)):
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "vuln/jwt-none-algo": {
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            ALGORITHM = "HS256"
            ALLOWED_ALGORITHMS = ["HS256", "HS512", "none"]


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    # Allowing 'none' algorithm permits unsigned tokens
                    payload = jwt.decode(
                        token,
                        SECRET_KEY,
                        algorithms=ALLOWED_ALGORITHMS,
                    )
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "vuln/auth-always-pass": {
        "backend/auth/dependencies.py": textwrap.dedent("""\
            from fastapi import Depends, HTTPException, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


            async def get_current_user(token: str = Depends(oauth2_scheme)):
                payload = verify_token(token)
                # Silent fallback to anonymous instead of raising 401
                return payload or {"sub": "anonymous", "role": "user"}


            async def require_admin(user=Depends(get_current_user)):
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "vuln/empty-password-allow": {
        "backend/routes/auth.py": textwrap.dedent("""\
            from fastapi import APIRouter
            from pydantic import BaseModel

            from backend.auth.jwt_handler import create_token

            router = APIRouter(prefix="/auth", tags=["auth"])


            class LoginRequest(BaseModel):
                username: str
                password: str


            # Simulated user store
            _USERS = {
                "alice": {"hashed_password": "$2b$12$hash_of_alice_password", "role": "admin"},
                "bob": {"hashed_password": "$2b$12$hash_of_bob_password", "role": "user"},
            }


            @router.post("/login")
            def login(credentials: LoginRequest):
                user = _USERS.get(credentials.username)
                if user is None:
                    return {"error": "Invalid username"}

                # Bug: empty password is accepted without verification
                if credentials.password == "" or True:
                    token = create_token({"sub": credentials.username, "role": user["role"]})
                    return {"access_token": token, "token_type": "bearer"}

                return {"error": "Invalid password"}
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes.auth import router as auth_router

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(auth_router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
        """),
    },

    "vuln/token-query-param": {
        "backend/auth/dependencies.py": textwrap.dedent("""\
            from typing import Optional

            from fastapi import Depends, HTTPException, Query, Request, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


            async def get_current_user(
                header_token: Optional[str] = Depends(oauth2_scheme),
                token: Optional[str] = Query(None, description="Bearer token as query param"),
            ):
                # Accepts token from query parameter — bypasses header-based security controls
                resolved_token = header_token or token
                if resolved_token is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                payload = verify_token(resolved_token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def require_admin(user=Depends(get_current_user)):
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "vuln/admin-self-promote": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user
            from backend.auth.jwt_handler import create_token

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.post("/make-admin")
            def make_self_admin(user=Depends(get_current_user)):
                \"\"\"Promote current user to admin — no secondary verification.\"\"\"
                new_token = create_token({"sub": user.get("sub"), "role": "admin"})
                return {
                    "message": "You are now an admin",
                    "access_token": new_token,
                    "token_type": "bearer",
                }
        """),
    },

    # ── Injection PRs (G3-G10) ───────────────────────────────────────────────

    "vuln/eval-injection": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/execute")
            def execute_expression(data: dict, user=Depends(require_admin)):
                expression = data.get("expression", "")
                try:
                    result = eval(expression)  # noqa: S307 — arbitrary code execution
                    return {"result": str(result), "expression": expression}
                except Exception as exc:
                    return {"error": str(exc)}
        """),
    },

    "vuln/pickle-deserialize": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/restore-session")
            def restore_session(data: dict, user=Depends(require_admin)):
                import base64
                import pickle
                session_data = data.get("session", "")
                try:
                    restored = pickle.loads(base64.b64decode(session_data))  # noqa: S301
                    return {"restored": str(restored)}
                except Exception as exc:
                    return {"error": str(exc)}
        """),
    },

    "vuln/yaml-unsafe-load": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/import-config")
            def import_config(data: dict, user=Depends(require_admin)):
                import yaml
                content = data.get("config_yaml", "")
                try:
                    # yaml.load without Loader=yaml.SafeLoader allows arbitrary code execution
                    config = yaml.load(content)  # noqa: S506
                    return {"imported_keys": list(config.keys()) if isinstance(config, dict) else []}
                except yaml.YAMLError as exc:
                    return {"error": str(exc)}
        """),
    },

    "vuln/path-traversal": {
        "backend/routes/files.py": textwrap.dedent("""\
            from fastapi import APIRouter, Query
            from fastapi.responses import PlainTextResponse

            router = APIRouter(prefix="/files", tags=["files"])


            @router.get("/read", response_class=PlainTextResponse)
            def read_file(path: str = Query(..., description="File path relative to static/")):
                \"\"\"Read a file — path is not validated, allowing directory traversal.\"\"\"
                try:
                    # No sanitization — ../../etc/passwd would work
                    with open(f"static/{path}", "r", encoding="utf-8") as f:
                        return f.read()
                except FileNotFoundError:
                    return "File not found"
                except PermissionError:
                    return "Permission denied"
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes import files

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(files.router)
        """),
    },

    "vuln/template-injection": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/greeting")
            def admin_greeting(name: str = "World", user=Depends(require_admin)):
                from jinja2 import Template
                # Template injection: user input is embedded directly in the template string
                template_str = f"Hello {{{{ {name} }}}}! Welcome to the admin panel."
                rendered = Template(template_str).render()
                return {"message": rendered}
        """),
    },

    "vuln/ldap-injection": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends, Query

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/search")
            def search_users_ldap(
                username: str = Query(...),
                user=Depends(get_current_user),
            ):
                # LDAP injection: username is not sanitized before filter construction
                ldap_filter = f"(uid={username})"
                # In a real app: ldap_conn.search(search_filter=ldap_filter)
                return {"filter_used": ldap_filter, "results": []}
        """),
    },

    "vuln/os-system-inject": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/system-check")
            def system_check(data: dict, user=Depends(require_admin)):
                import os
                host = data.get("host", "")
                # OS command injection: host is not sanitized
                exit_code = os.system(f"check_host {host}")
                return {"host": host, "exit_code": exit_code}
        """),
    },

    "vuln/xml-injection": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/import-xml")
            def import_xml(data: dict, user=Depends(require_admin)):
                import xml.etree.ElementTree as ET
                xml_content = data.get("xml_data", "")
                try:
                    # XXE vulnerability: external entity processing not disabled
                    root = ET.fromstring(xml_content)
                    tag_names = [child.tag for child in root]
                    return {"root_tag": root.tag, "children": tag_names}
                except ET.ParseError as exc:
                    return {"error": str(exc)}
        """),
    },

    # ── Additional Safe PRs (S31-S35) ────────────────────────────────────────

    "safe/typing-hints": {
        "backend/auth/dependencies.py": textwrap.dedent("""\
            from fastapi import Depends, HTTPException, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


            async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
                payload: dict | None = verify_token(token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def require_admin(user: dict = Depends(get_current_user)) -> dict:
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "safe/ci-config": {
        "Makefile": textwrap.dedent("""\
            .PHONY: install test lint run

            install:
            \tpip install -r requirements.txt

            test:
            \tpython -m pytest tests/ -v

            lint:
            \tpython -m flake8 backend/ --max-line-length 100

            run:
            \tuvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
        """),
    },

    "safe/user-me-extend": {
        "backend/routes/users.py": textwrap.dedent("""\
            from datetime import datetime, timezone
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {
                    "user": user,
                    "last_login": datetime.now(timezone.utc).isoformat(),
                    "session_valid": True,
                }


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}


            @router.get("/profile")
            def get_profile(user=Depends(get_current_user)):
                return {"profile": {"sub": user.get("sub"), "role": user.get("role")}}
        """),
    },

    "safe/constants": {
        "backend/constants.py": textwrap.dedent("""\
            \"\"\"Application-wide constants.\"\"\"

            # Token types
            TOKEN_TYPE_BEARER = "bearer"
            TOKEN_TYPE_REFRESH = "refresh"

            # Role names
            ROLE_ADMIN = "admin"
            ROLE_USER = "user"
            ROLE_GUEST = "guest"

            # Pagination defaults
            DEFAULT_PAGE_SIZE = 20
            MAX_PAGE_SIZE = 100

            # Cache TTLs (seconds)
            CACHE_TTL_SHORT = 60
            CACHE_TTL_MEDIUM = 300
            CACHE_TTL_LONG = 3600

            # HTTP status messages
            MSG_NOT_FOUND = "Resource not found"
            MSG_UNAUTHORIZED = "Authentication required"
            MSG_FORBIDDEN = "Insufficient permissions"
            MSG_BAD_REQUEST = "Invalid request parameters"
        """),
    },

    "safe/openapi-metadata": {
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users

            _TAGS_METADATA = [
                {"name": "health", "description": "Service health checks (public)"},
                {"name": "public", "description": "Publicly accessible endpoints"},
                {"name": "users", "description": "User profile management (requires authentication)"},
                {"name": "admin", "description": "Administration endpoints (requires admin role)"},
                {"name": "products", "description": "Product catalog management"},
            ]

            app = FastAPI(
                title="vibeguard-test-app",
                version="1.0.0",
                description="VibeGuard evaluation FastAPI application",
                openapi_tags=_TAGS_METADATA,
                contact={"name": "VibeGuard Team", "email": "security@example.com"},
                license_info={"name": "MIT"},
            )

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
        """),
    },

    # ── Additional Authorization PRs (A26-A28) ───────────────────────────────

    "vuln/admin-patch-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.patch("/users/{user_id}/status")
            def update_user_status(user_id: int, data: dict):
                new_status = data.get("status", "active")
                # Missing authentication — any caller can activate/deactivate users
                return {"user_id": user_id, "status": new_status, "updated": True}
        """),
    },

    "vuln/order-idor": {
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}


            @router.get("/orders/{order_id}")
            def get_order(order_id: int, user=Depends(get_current_user)):
                # IDOR: no check that this order belongs to the current user
                return {
                    "order_id": order_id,
                    "user_id": 42,
                    "items": [{"product": "Widget A", "qty": 2, "price": 19.98}],
                    "total": 19.98,
                    "status": "shipped",
                }
        """),
    },

    "vuln/config-write-no-auth": {
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.put("/feature-flags")
            def update_feature_flags(data: dict):
                flags = data.get("flags", {})
                # Missing authentication — any caller can toggle feature flags
                return {"updated_flags": flags, "success": True}
        """),
    },

    # ── Additional Secret Exposure PRs (E16-E17) ─────────────────────────────

    "vuln/npm-token": {
        ".npmrc": textwrap.dedent("""\
            registry=https://registry.npmjs.org/
            //registry.npmjs.org/:_authToken=npm_abcDEFghiJKLmnoPQRstuVWXyz1234567890AB
            always-auth=true
        """),
    },

    "vuln/firebase-key": {
        "backend/config.py": _BASE_CONFIG + textwrap.dedent("""\

            # Firebase configuration
            FIREBASE_API_KEY = "AIzaSyAbcDEFghijklMNOpqrstUVwxyz1234567"
            FIREBASE_AUTH_DOMAIN = "my-prod-app.firebaseapp.com"
            FIREBASE_PROJECT_ID = "my-prod-app"
            FIREBASE_STORAGE_BUCKET = "my-prod-app.appspot.com"
            FIREBASE_MESSAGING_SENDER_ID = "123456789012"
            FIREBASE_APP_ID = "1:123456789012:web:abcdef1234567890abcdef"
        """),
    },

    # ── New cases (eval/case-NNN entries without old-name equivalents) ─────

    "eval/case-021": {  # S05: alembic migration
        "migrations/versions/0001_initial.py": textwrap.dedent("""\
            \"\"\"initial schema migration\"\"\"
            from alembic import op
            import sqlalchemy as sa

            revision = '0001'
            down_revision = None

            def upgrade():
                op.create_table('users',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('sub', sa.String(), nullable=False),
                    sa.Column('role', sa.String(), nullable=False, server_default='user'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('sub'),
                )

            def downgrade():
                op.drop_table('users')
        """),
    },

    "eval/case-026": {  # S06: .gitignore update
        ".gitignore": textwrap.dedent("""\
            # Python
            __pycache__/
            *.py[cod]
            *.egg-info/
            dist/
            build/
            .eggs/
            .pytest_cache/
            .mypy_cache/
            htmlcov/
            .coverage

            # Environment
            .env
            .env.*
            !.env.example
            venv/
            .venv/
            env/

            # IDE
            .idea/
            .vscode/
            *.swp
            *.swo

            # OS
            .DS_Store
            Thumbs.db

            # Project specific
            *.db
            *.sqlite3
            logs/
            *.log
        """),
    },

    "eval/case-031": {  # S07: docs/API.md update (distinct from S03 docs/ case)
        "docs/ARCHITECTURE.md": textwrap.dedent("""\
            # Architecture Overview

            ## Components

            ### Auth Layer
            - `backend/auth/jwt_handler.py` — JWT create/verify
            - `backend/auth/dependencies.py` — FastAPI Depends: `get_current_user`, `require_admin`

            ### Routes
            | Prefix | Auth Required | Role |
            |--------|--------------|------|
            | /public | None | — |
            | /health | None | — |
            | /users | Bearer token | user |
            | /admin | Bearer token | admin |
            | /products | Bearer token | admin |

            ### Security Model
            All protected routes use FastAPI `Depends()` for auth injection.
            No route handler should call auth functions directly.
        """),
    },

    "eval/case-036": {  # S08: second tests/ case
        "tests/test_admin.py": textwrap.dedent("""\
            import pytest
            from fastapi.testclient import TestClient
            from backend.main import app

            client = TestClient(app)


            def test_admin_requires_auth():
                response = client.get("/admin/dashboard")
                assert response.status_code == 401


            def test_admin_settings_requires_auth():
                response = client.put("/admin/settings", json={})
                assert response.status_code == 401


            def test_admin_logs_requires_auth():
                response = client.get("/admin/logs")
                assert response.status_code == 401


            def test_admin_announcements_requires_auth():
                response = client.post("/admin/announcements", json={})
                assert response.status_code == 401
        """),
    },

    "eval/case-041": {  # S09: migrations/add_index.sql
        "migrations/0002_add_indexes.sql": textwrap.dedent("""\
            -- Add performance indexes
            CREATE INDEX IF NOT EXISTS idx_users_sub ON users(sub);
            CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
            CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
            CREATE INDEX IF NOT EXISTS idx_announcements_created_by
                ON announcements(created_by);
        """),
    },

    "eval/case-046": {  # S10: tests/test_products.py
        "tests/test_products.py": textwrap.dedent("""\
            import pytest
            from fastapi.testclient import TestClient
            from backend.main import app

            client = TestClient(app)


            def test_products_list_requires_auth():
                response = client.get("/products/")
                assert response.status_code == 401


            def test_products_create_requires_auth():
                response = client.post("/products/", json={"name": "test", "price": 9.99})
                assert response.status_code == 401


            def test_products_delete_requires_auth():
                response = client.delete("/products/1")
                assert response.status_code == 401
        """),
    },

    "eval/case-048": {  # T10: JWT signing with hardcoded empty string
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = ""
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "eval/case-053": {  # T11: MFA bypass with magic code
        "backend/auth/mfa.py": textwrap.dedent("""\
            import os

            MAGIC_BYPASS_CODE = "000000"


            def verify_mfa_code(user_id: str, code: str) -> bool:
                \"\"\"Verify MFA code for user. Returns True if valid.\"\"\"
                if code == MAGIC_BYPASS_CODE:
                    return True
                stored_code = _get_stored_code(user_id)
                return stored_code == code


            def _get_stored_code(user_id: str) -> str | None:
                return None
        """),
    },

    "eval/case-054": {  # G11: marshal.loads deserialization
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/restore-data")
            def restore_data(data: dict, user=Depends(require_admin)):
                import marshal, base64
                raw = base64.b64decode(data.get("payload", ""))
                restored = marshal.loads(raw)
                return {"restored": str(restored)}
        """),
    },

    "eval/case-058": {  # T12: password check always True for non-empty
        "backend/auth/dependencies.py": textwrap.dedent("""\
            from fastapi import Depends, HTTPException, status
            from fastapi.security import OAuth2PasswordBearer

            from backend.auth.jwt_handler import verify_token

            oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


            def check_password(plain: str, hashed: str) -> bool:
                if not plain:
                    return False
                return True


            async def get_current_user(token: str = Depends(oauth2_scheme)):
                payload = verify_token(token)
                if payload is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid authentication credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return payload


            async def require_admin(user=Depends(get_current_user)):
                if user.get("role") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin access required",
                    )
                return user
        """),
    },

    "eval/case-059": {  # G12: SSRF via unvalidated user URL
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/fetch-url")
            def fetch_url(data: dict, user=Depends(require_admin)):
                import urllib.request
                url = data.get("url", "")
                with urllib.request.urlopen(url) as resp:
                    content = resp.read().decode()[:1000]
                return {"content": content}
        """),
    },

    "eval/case-063": {  # T13: admin creation without email verification
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.post("/create-admin")
            def create_admin_account(data: dict):
                username = data.get("username")
                password = data.get("password")
                return {"created": True, "username": username, "role": "admin"}
        """),
    },

    "eval/case-064": {  # G13: jinja2 autoescape=False + user input
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/render")
            def render_template(template: str, user=Depends(require_admin)):
                from jinja2 import Environment
                env = Environment(autoescape=False)
                result = env.from_string(template).render()
                return {"rendered": result}
        """),
    },

    "eval/case-068": {  # T14: logout without token invalidation
        "backend/routes/auth.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/auth", tags=["auth"])


            @router.post("/logout")
            def logout(user=Depends(get_current_user)):
                return {"message": "Logged out successfully"}
        """),
        "backend/main.py": textwrap.dedent("""\
            from fastapi import FastAPI

            from backend.routes import admin, health, products, public, users
            from backend.routes import auth as auth_router

            app = FastAPI(title="vibeguard-test-app", version="1.0.0")

            app.include_router(health.router)
            app.include_router(public.router)
            app.include_router(users.router)
            app.include_router(admin.router)
            app.include_router(products.router)
            app.include_router(auth_router.router)
        """),
    },

    "eval/case-069": {  # G14: f-string SQL for products (distinct from G01 user search)
        "backend/routes/products.py": textwrap.dedent("""\
            import sqlite3

            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import require_admin

            router = APIRouter(prefix="/products", tags=["products"])


            @router.get("/search")
            def search_products(q: str, user=Depends(require_admin)):
                conn = sqlite3.connect("app.db")
                cursor = conn.cursor()
                query = f"SELECT * FROM products WHERE name = '{q}'"
                cursor.execute(query)
                results = cursor.fetchall()
                conn.close()
                return {"results": results}
        """),
    },

    "eval/case-073": {  # T15: timing-vulnerable password comparison
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None


            def verify_password(plain: str, stored: str) -> bool:
                for a, b in zip(plain, stored):
                    if a != b:
                        return False
                return len(plain) == len(stored)
        """),
    },

    "eval/case-074": {  # G15: os.popen log search injection
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            @router.get("/logs/search")
            def search_logs(pattern: str, user=Depends(require_admin)):
                import os
                result = os.popen(f"grep {pattern} /var/log/app.log").read()
                return {"matches": result}
        """),
    },

    "eval/case-093": {  # S33: JWT_SECRET empty string default (safe hard-negative)
        "backend/auth/jwt_handler.py": textwrap.dedent("""\
            import os
            from datetime import datetime, timedelta

            import jwt

            SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
            ALGORITHM = "HS256"


            def create_token(data: dict, expires_minutes: int = 30) -> str:
                payload = data.copy()
                payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
                return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


            def verify_token(token: str) -> dict | None:
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    return payload
                except jwt.PyJWTError:
                    return None
        """),
    },

    "eval/case-094": {  # S34: parameterized SQL (safe hard-negative)
        "backend/routes/users.py": textwrap.dedent("""\
            import sqlite3

            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}


            @router.get("/search")
            def search_users(q: str, user=Depends(get_current_user)):
                conn = sqlite3.connect("app.db")
                cursor = conn.cursor()
                cursor.execute("SELECT id, sub FROM users WHERE sub = %s", (q,))
                results = cursor.fetchall()
                conn.close()
                return {"results": results}
        """),
    },

    "eval/case-095": {  # S35: Firebase public config (safe hard-negative)
        "backend/config.py": textwrap.dedent("""\
            import os

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

            FIREBASE_CONFIG = {
                "apiKey": "AIzaSyC-example-public-key-not-a-secret",
                "authDomain": "vibeguard-test-app.firebaseapp.com",
                "projectId": "vibeguard-test-app",
                "storageBucket": "vibeguard-test-app.appspot.com",
                "messagingSenderId": "123456789012",
                "appId": "1:123456789012:web:abcdef1234567890",
            }
        """),
    },

    "eval/case-096": {  # S36: example token in docstring (safe hard-negative)
        "backend/routes/users.py": textwrap.dedent("""\
            from fastapi import APIRouter, Depends

            from backend.auth.dependencies import get_current_user

            router = APIRouter(prefix="/users", tags=["users"])


            @router.get("/me")
            def get_my_profile(user=Depends(get_current_user)):
                \"\"\"
                Get current user profile.

                Example request:
                    GET /users/me
                    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example

                Returns the authenticated user's profile data.
                \"\"\"
                return {"user": user}


            @router.put("/me")
            def update_my_profile(data: dict, user=Depends(get_current_user)):
                return {"updated": True}


            @router.get("/me/orders")
            def get_my_orders(user=Depends(get_current_user)):
                return {"orders": []}
        """),
    },

    "eval/case-098": {  # S38: require_superadmin wrapping require_admin (safe hard-negative)
        "backend/routes/admin.py": _BASE_ADMIN + textwrap.dedent("""\

            async def require_superadmin(user=Depends(require_admin)):
                \"\"\"Superadmin tier: requires admin role + sub present.\"\"\"
                if not user.get("sub"):
                    from fastapi import HTTPException, status
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Superadmin access required",
                    )
                return user


            @router.delete("/system/reset")
            async def system_reset(user=Depends(require_superadmin)):
                return {"reset": True, "by": user.get("sub")}
        """),
    },

    "eval/case-099": {  # S39: REDIS_URL localhost default (safe hard-negative)
        "backend/config.py": textwrap.dedent("""\
            import os

            APP_NAME = "vibeguard-test-app"
            DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
            DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
            JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
            JWT_ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
            REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "300"))
        """),
    },
}

# Maps new eval/case-NNN branch names → existing BRANCH_CHANGES keys
# This allows setup_test_repo.py to push branches under new neutral names
BRANCH_RENAME_MAP: dict[str, str] = {
    "eval/case-001": "vuln/admin-no-auth",
    "eval/case-002": "safe/readme-update",
    "eval/case-003": "vuln/no-login-check",
    "eval/case-004": "vuln/sql-injection",
    "eval/case-005": "vuln/hardcoded-key",
    "eval/case-006": "safe/test-addition",
    "eval/case-007": "vuln/admin-wrong-level",
    "eval/case-008": "vuln/token-verify-skip",
    "eval/case-009": "vuln/command-injection",
    "eval/case-010": "vuln/jwt-secret",
    "eval/case-011": "safe/docs-update",
    "eval/case-012": "vuln/admin-get-no-auth",
    "eval/case-013": "vuln/session-bypass",
    "eval/case-014": "vuln/eval-injection",
    "eval/case-015": "vuln/db-password",
    "eval/case-016": "safe/migration",
    "eval/case-017": "vuln/admin-post-no-auth",
    "eval/case-018": "vuln/jwt-no-expiry",
    "eval/case-019": "vuln/pickle-deserialize",
    "eval/case-020": "vuln/env-in-code",
    "eval/case-022": "vuln/remove-auth",
    "eval/case-023": "vuln/debug-bypass",
    "eval/case-024": "vuln/yaml-unsafe-load",
    "eval/case-025": "vuln/token-in-comment",
    "eval/case-027": "vuln/admin-multiple",
    "eval/case-028": "vuln/jwt-none-algo",
    "eval/case-029": "vuln/path-traversal",
    "eval/case-030": "vuln/env-fallback-secret",
    "eval/case-032": "vuln/middleware-remove",
    "eval/case-033": "vuln/auth-always-pass",
    "eval/case-034": "vuln/template-injection",
    "eval/case-035": "vuln/slack-webhook",
    "eval/case-037": "vuln/idor-user-data",
    "eval/case-038": "vuln/empty-password-allow",
    "eval/case-039": "vuln/ldap-injection",
    "eval/case-040": "vuln/sendgrid-key",
    "eval/case-042": "vuln/report-wrong-level",
    "eval/case-043": "vuln/token-query-param",
    "eval/case-044": "vuln/os-system-inject",
    "eval/case-045": "vuln/multiple-secrets",
    "eval/case-047": "vuln/export-no-auth",
    "eval/case-049": "vuln/xml-injection",
    "eval/case-050": "vuln/stripe-secret",
    "eval/case-051": "safe/public-endpoint",
    "eval/case-052": "vuln/user-role-change",
    "eval/case-055": "vuln/private-key-inline",
    "eval/case-056": "safe/admin-with-auth",
    "eval/case-057": "vuln/internal-api-no-auth",
    "eval/case-060": "vuln/oauth-credentials",
    "eval/case-061": "safe/user-endpoint",
    "eval/case-062": "vuln/debug-endpoint",
    "eval/case-065": "vuln/redis-password",
    "eval/case-066": "safe/refactor-logic",
    "eval/case-067": "vuln/admin-self-promote",
    "eval/case-070": "vuln/twilio-credentials",
    "eval/case-071": "safe/config-safe",
    "eval/case-072": "vuln/admin-search-no-auth",
    "eval/case-075": "vuln/cloud-multi-secret",
    "eval/case-076": "safe/pagination",
    "eval/case-077": "safe/new-product-endpoint",
    "eval/case-078": "safe/health-extend",
    "eval/case-079": "safe/error-handler",
    "eval/case-080": "safe/admin-audit",
    "eval/case-081": "safe/bcrypt-upgrade",
    "eval/case-082": "safe/rate-limiting",
    "eval/case-083": "safe/cors-config",
    "eval/case-084": "safe/security-headers",
    "eval/case-085": "safe/env-validation",
    "eval/case-086": "safe/requirements-update",
    "eval/case-087": "safe/input-validation",
    "eval/case-088": "safe/password-policy",
    "eval/case-089": "safe/logging-setup",
    "eval/case-090": "safe/db-pool",
    "eval/case-091": "safe/jwt-rename",
    "eval/case-092": "safe/custom-auth",
    "eval/case-097": "safe/auth-refactor",
    "eval/case-100": "safe/ci-config",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list[str], cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def create_github_repo(owner_repo: str, token: str) -> None:
    import urllib.request
    import urllib.error

    owner, repo = owner_repo.split("/", 1)
    url = f"https://api.github.com/user/repos"
    payload = json.dumps({"name": repo, "private": True, "auto_init": False}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"  Created repo: {owner_repo}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if "already exists" in body or e.code == 422:
            print(f"  Repo {owner_repo} already exists, continuing.")
        else:
            raise RuntimeError(f"Failed to create repo: {e.code} {body}") from e


def copy_app_to_repo(repo_dir: str) -> None:
    for src in APP_DIR.rglob("*"):
        if src.is_file():
            rel = src.relative_to(APP_DIR)
            dst = Path(repo_dir) / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def write_branch_files(repo_dir: str, changes: dict[str, str]) -> None:
    for filepath, content in changes.items():
        full_path = Path(repo_dir) / filepath
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Setup vibeguard-test-app repository")
    parser.add_argument("--repo", required=True, help="GitHub repo in owner/name format")
    parser.add_argument("--token", required=True, help="GitHub personal access token")
    parser.add_argument("--create", action="store_true", help="Create the repo via GitHub API")
    args = parser.parse_args()

    if "/" not in args.repo:
        sys.exit("--repo must be in owner/repo-name format")

    if args.create:
        print("▶ Creating GitHub repo...")
        create_github_repo(args.repo, args.token)

    tmp = tempfile.mkdtemp(prefix="vg-setup-")
    print(f"▶ Working directory: {tmp}")

    try:
        clone_url = f"https://{args.token}@github.com/{args.repo}.git"
        repo_dir = os.path.join(tmp, "repo")

        # Clone (or init + add remote if empty)
        print("▶ Cloning repository...")
        result = run(["git", "clone", clone_url, repo_dir], check=False)
        if result.returncode != 0:
            os.makedirs(repo_dir)
            run(["git", "init", "-b", "main"], cwd=repo_dir)
            run(["git", "remote", "add", "origin", clone_url], cwd=repo_dir)

        run(["git", "config", "user.email", "vibeguard-setup@example.com"], cwd=repo_dir)
        run(["git", "config", "user.name", "VibeGuard Setup"], cwd=repo_dir)

        # Push base app to main
        print("▶ Pushing base app to main...")
        copy_app_to_repo(repo_dir)
        run(["git", "add", "-A"], cwd=repo_dir)
        run(["git", "commit", "-m", "chore: initial vibeguard-test-app base"], cwd=repo_dir, check=False)
        run(["git", "push", "-u", "origin", "main", "--force"], cwd=repo_dir)

        # Load manifest for commit messages and new branch names
        manifest_path = SCRIPT_DIR / "manifest.json"
        commit_messages: dict[str, str] = {}
        if manifest_path.exists():
            import json as _json
            with open(manifest_path) as _f:
                _manifest = _json.load(_f)
            for _tc in _manifest.get("test_cases", []):
                commit_messages[_tc["branch"]] = _tc.get("commit_message", f"feat: {_tc['branch']}")

        # Build full branch set: renamed branches + direct entries
        all_branches: dict[str, dict[str, str]] = {}
        for new_branch, old_key in BRANCH_RENAME_MAP.items():
            if old_key in BRANCH_CHANGES:
                all_branches[new_branch] = BRANCH_CHANGES[old_key]
        for branch, changes in BRANCH_CHANGES.items():
            if branch.startswith("eval/"):
                all_branches[branch] = changes

        print(f"▶ Creating {len(all_branches)} test branches...")
        for branch, changes in all_branches.items():
            commit_msg = commit_messages.get(branch, f"feat: update {branch.split('/')[-1]}")
            print(f"  • {branch}")
            run(["git", "checkout", "-b", branch, "main"], cwd=repo_dir)
            write_branch_files(repo_dir, changes)
            run(["git", "add", "-A"], cwd=repo_dir)
            run(["git", "commit", "-m", commit_msg], cwd=repo_dir)
            run(["git", "push", "origin", branch, "--force"], cwd=repo_dir)
            run(["git", "checkout", "main"], cwd=repo_dir)

        print(f"\n✅ Done. {len(all_branches)} branches pushed to {args.repo}")
        print(f"   Next: python evaluation/test_runner.py --repo {args.repo} --token <token>")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
