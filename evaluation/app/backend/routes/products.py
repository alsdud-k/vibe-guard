from fastapi import APIRouter, Depends

from backend.auth.dependencies import require_admin

router = APIRouter(prefix="/products", tags=["products"])


@router.get("/")
def list_products(user=Depends(require_admin)):
    return {"products": []}


@router.post("/")
def create_product(data: dict, user=Depends(require_admin)):
    return {"created": True}


@router.put("/{product_id}")
def update_product(product_id: int, data: dict, user=Depends(require_admin)):
    return {"updated": product_id}


@router.delete("/{product_id}")
def delete_product(product_id: int, user=Depends(require_admin)):
    return {"deleted": product_id}
