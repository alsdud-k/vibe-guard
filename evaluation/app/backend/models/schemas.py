from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str
    role: str = "user"


class ProductCreate(BaseModel):
    name: str
    price: float
    description: str = ""


class AnnouncementCreate(BaseModel):
    title: str
    body: str


class SettingsUpdate(BaseModel):
    key: str
    value: str
