# vibeguard-test-app

VibeGuard 평가용 FastAPI 테스트 애플리케이션.

## 구조

- `backend/auth/` — JWT 인증 + 권한 의존성 (`get_current_user`, `require_admin`)
- `backend/routes/admin.py` — 관리자 전용 엔드포인트 (모두 `require_admin` 적용)
- `backend/routes/products.py` — 상품 CRUD (`require_admin`)
- `backend/routes/users.py` — 사용자 프로필 (`get_current_user`)
- `backend/routes/public.py` — 공개 엔드포인트 (인증 불필요)
- `backend/routes/health.py` — 헬스체크 (인증 불필요)

## 실행

```bash
pip install fastapi uvicorn python-jose
uvicorn backend.main:app --reload
```

## 보안 정책

- `/admin/*` — `require_admin` 필수
- `/internal/*` — `require_admin` 필수
- `/users/*` — `get_current_user` 필수
- `/public/*`, `/health`, `/ready` — 인증 불필요
