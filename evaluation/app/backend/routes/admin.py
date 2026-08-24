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
