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
        run(["git", "commit", "-m", "chore: initial vibeguard-test-app base"], cwd=repo_dir)
        run(["git", "push", "-u", "origin", "main", "--force"], cwd=repo_dir)

        # Create all test branches
        print(f"▶ Creating {len(BRANCH_CHANGES)} test branches...")
        for branch, changes in BRANCH_CHANGES.items():
            print(f"  • {branch}")
            run(["git", "checkout", "-b", branch, "main"], cwd=repo_dir)
            write_branch_files(repo_dir, changes)
            run(["git", "add", "-A"], cwd=repo_dir)
            run(["git", "commit", "-m", f"test: {branch}"], cwd=repo_dir)
            run(["git", "push", "origin", branch], cwd=repo_dir)
            run(["git", "checkout", "main"], cwd=repo_dir)

        print(f"\n✅ Done. {len(BRANCH_CHANGES)} branches pushed to {args.repo}")
        print(f"   Next: python evaluation/test_runner.py --repo {args.repo} --token <token>")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
