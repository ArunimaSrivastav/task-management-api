import pytest
from fastapi.testclient import TestClient
from main import app
from database import Base, engine
from fastapi.testclient import TestClient
from main import app
from database import Base, engine
import models

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_create_user():
    response = client.post(
        "/users/",
        json={"username": "testuser", "email": "test@example.com", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert "id" in data

def test_login():
    # First create a user
    client.post(
        "/users/",
        json={"username": "testuser", "email": "test@example.com", "password": "testpassword"}
    )
    
    # Then try to login
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_read_users_me():
    # First create a user and get a token
    client.post(
        "/users/",
        json={"username": "testuser", "email": "test@example.com", "password": "testpassword"}
    )
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"}
    )
    token = response.json()["access_token"]
    
    # Then try to access the /users/me endpoint
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "user"