from fastapi import APIRouter

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/")
def public_index():
    return {"message": "Welcome to vibeguard-test-app"}


@router.get("/status")
def public_status():
    return {"status": "ok"}
