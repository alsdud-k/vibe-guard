from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check():
    return {"status": "healthy"}


@router.get("/ready")
def readiness_check():
    return {"status": "ready"}
