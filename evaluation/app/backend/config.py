import os

APP_NAME = "vibeguard-test-app"
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
