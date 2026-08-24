from fastapi import FastAPI

from backend.routes import admin, health, products, public, users

app = FastAPI(title="vibeguard-test-app", version="1.0.0")

app.include_router(health.router)
app.include_router(public.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(products.router)
