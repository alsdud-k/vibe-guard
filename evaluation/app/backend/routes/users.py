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
