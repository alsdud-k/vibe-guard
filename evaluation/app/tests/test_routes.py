import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_public_status():
    response = client.get("/public/status")
    assert response.status_code == 200


def test_admin_requires_auth():
    response = client.get("/admin/dashboard")
    assert response.status_code == 401


def test_users_requires_auth():
    response = client.get("/users/me")
    assert response.status_code == 401
