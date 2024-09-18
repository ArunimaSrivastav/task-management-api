import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import os

from main import app
from database import Base, get_db
from models import User, Task, CustomField, Category, Label
from schemas import TaskType, UserRole

# Test database file
TEST_DB_FILE = "test.db"

# Test database URL
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_FILE}"

# Create a test engine
engine = create_engine(TEST_DATABASE_URL)

# Create TestingSessionLocal
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the get_db function for testing
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(test_db):
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def test_db_setup_teardown():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)

@pytest.fixture(scope="function")
def test_user(client):
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword",
        "role": UserRole.USER
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200, f"Failed to create user. Response: {response.content}"
    return response.json()

@pytest.fixture(scope="function")
def user_token(client, test_user):
    response = client.post("/token", data={"username": test_user["username"], "password": "testpassword"})
    assert response.status_code == 200, f"Failed to get token. Response: {response.content}"
    return response.json()["access_token"]

def test_create_user(client):
    user_data = {
        "username": "newuser",
        "email": "new@example.com",
        "password": "newpassword",
        "role": UserRole.USER
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200, f"Failed to create user. Response: {response.content}"
    assert response.json()["username"] == user_data["username"]
    assert response.json()["email"] == user_data["email"]
    assert response.json()["role"] == UserRole.USER
    assert "id" in response.json()

def test_login(client, test_user):
    response = client.post("/token", data={"username": test_user["username"], "password": "testpassword"})
    assert response.status_code == 200, f"Failed to login. Response: {response.content}"
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_create_task(client, user_token):
    task_data = {
        "title": "Test Task",
        "description": "This is a test task",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK,
        "custom_fields": [
            {"name": "Priority", "field_type": "string", "value": "High"}
        ]
    }
    response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to create task. Response: {response.content}"
    assert response.json()["title"] == task_data["title"]
    assert response.json()["task_type"] == TaskType.TASK
    assert len(response.json()["custom_fields"]) == 1
    assert "id" in response.json()

def test_read_tasks(client, user_token):
    # First, create a task to ensure there's at least one
    task_data = {
        "title": "Task for Reading",
        "description": "This task is for the read test",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK
    }
    client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    
    response = client.get("/tasks/", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to read tasks. Response: {response.content}"
    assert isinstance(response.json(), list)
    assert len(response.json()) > 0

def test_update_task(client, user_token):
    # First, create a task
    task_data = {
        "title": "Task to Update",
        "description": "This task will be updated",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK
    }
    create_response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert create_response.status_code == 200, f"Failed to create task for update. Response: {create_response.content}"
    task_id = create_response.json()["id"]

    # Now, update the task
    update_data = {
        "title": "Updated Task",
        "status": "In Progress",
        "task_type": TaskType.TASK
    }
    response = client.put(f"/tasks/{task_id}", json=update_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to update task. Response: {response.content}"
    assert response.json()["title"] == update_data["title"]
    assert response.json()["status"] == update_data["status"]

def test_delete_task(client, user_token):
    # First, create a task
    task_data = {
        "title": "Task to Delete",
        "description": "This task will be deleted",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK
    }
    create_response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert create_response.status_code == 200, f"Failed to create task for deletion. Response: {create_response.content}"
    task_id = create_response.json()["id"]

    # Now, delete the task
    response = client.delete(f"/tasks/{task_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to delete task. Response: {response.content}"

    # Verify the task is deleted
    get_response = client.get(f"/tasks/{task_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert get_response.status_code in [404, 405], f"Unexpected response after deletion. Status: {get_response.status_code}, Response: {get_response.content}"

def test_create_subtask(client, user_token):
    # First, create a parent task
    parent_task_data = {
        "title": "Parent Task",
        "description": "This is a parent task",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK
    }
    parent_response = client.post("/tasks/", json=parent_task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert parent_response.status_code == 200, f"Failed to create parent task. Response: {parent_response.content}"
    parent_id = parent_response.json()["id"]

    # Now, create a subtask
    subtask_data = {
        "title": "Subtask",
        "description": "This is a subtask",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.SUBTASK,
        "parent_id": parent_id
    }
    response = client.post("/tasks/", json=subtask_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to create subtask. Response: {response.content}"
    assert response.json()["title"] == subtask_data["title"]
    assert response.json()["parent_id"] == parent_id

def test_read_task_hierarchy(client, user_token):
    # First, create a task hierarchy
    parent_task_data = {
        "title": "Parent Task",
        "description": "This is a parent task",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK
    }
    parent_response = client.post("/tasks/", json=parent_task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert parent_response.status_code == 200
    parent_id = parent_response.json()["id"]

    subtask_data = {
        "title": "Subtask",
        "description": "This is a subtask",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.SUBTASK,
        "parent_id": parent_id
    }
    client.post("/tasks/", json=subtask_data, headers={"Authorization": f"Bearer {user_token}"})

    response = client.get("/tasks/hierarchy/", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to read task hierarchy. Response: {response.content}"
    assert isinstance(response.json(), list)
    assert len(response.json()) > 0
    # Check if the hierarchy is correctly structured
    for task in response.json():
        if "children" in task:
            assert isinstance(task["children"], list)

def test_create_and_update_custom_field(client, user_token):
    # First, create a task
    task_data = {
        "title": "Task with Custom Field",
        "description": "This task will have a custom field",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK
    }
    task_response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert task_response.status_code == 200, f"Failed to create task for custom field. Response: {task_response.content}"
    task_id = task_response.json()["id"]

    # Create a custom field
    custom_field_data = {
        "name": "Test Field",
        "field_type": "string",
        "value": "Test Value"
    }
    create_response = client.post(f"/tasks/{task_id}/custom-fields/", json=custom_field_data, headers={"Authorization": f"Bearer {user_token}"})
    assert create_response.status_code == 200, f"Failed to create custom field. Response: {create_response.content}"
    field_id = create_response.json()["id"]

    # Update the custom field
    update_data = {
        "name": "Updated Field",
        "field_type": "string",
        "value": "New Value"
    }
    update_response = client.put(f"/tasks/{task_id}/custom-fields/{field_id}", json=update_data, headers={"Authorization": f"Bearer {user_token}"})
    assert update_response.status_code == 200, f"Failed to update custom field. Response: {update_response.content}"
    assert update_response.json()["name"] == update_data["name"]
    assert update_response.json()["value"] == update_data["value"]

def test_user_roles_and_permissions(client):
    # Create an admin user
    admin_data = {
        "username": "admin",
        "email": "admin@example.com",
        "password": "adminpass",
        "role": UserRole.ADMIN
    }
    admin_response = client.post("/users/", json=admin_data)
    assert admin_response.status_code == 200, f"Failed to create admin user. Response: {admin_response.content}"
    print(f"Admin user created: {admin_response.json()}")
    
    # Login as admin
    admin_token_response = client.post("/token", data={"username": "admin", "password": "adminpass"})
    assert admin_token_response.status_code == 200, f"Failed to login as admin. Response: {admin_token_response.content}"
    admin_token = admin_token_response.json()["access_token"]

    # Test admin-only endpoint (get all users)
    admin_get_users_response = client.get("/users/", headers={"Authorization": f"Bearer {admin_token}"})
    print(f"Admin get users response: {admin_get_users_response.content}")
    assert admin_get_users_response.status_code == 200, f"Admin failed to get users. Response: {admin_get_users_response.content}"

    # Create a regular user using admin token
    user_data = {
        "username": "user",
        "email": "user@example.com",
        "password": "userpass",
        "role": UserRole.USER
    }
    user_response = client.post("/users/", json=user_data, headers={"Authorization": f"Bearer {admin_token}"})
    assert user_response.status_code == 200, f"Failed to create regular user. Response: {user_response.content}"

    # Login as regular user
    user_token_response = client.post("/token", data={"username": "user", "password": "userpass"})
    assert user_token_response.status_code == 200, f"Failed to login as regular user. Response: {user_token_response.content}"
    user_token = user_token_response.json()["access_token"]

    # Test admin-only endpoint (get all users)
    admin_get_users_response = client.get("/users/", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_get_users_response.status_code == 200, f"Admin failed to get users. Response: {admin_get_users_response.content}"

    # Test regular user accessing admin-only endpoint
    user_get_users_response = client.get("/users/", headers={"Authorization": f"Bearer {user_token}"})
    assert user_get_users_response.status_code == 403, f"Regular user should not be able to access admin endpoint. Response: {user_get_users_response.content}"

def test_read_user(client: TestClient, user_token: str):
    print("\n--- Testing read_user ---")

    # First, create a new user
    user_data = {
        "username": "testuser2",
        "email": "test2@example.com",
        "password": "testpassword2",
        "role": UserRole.USER
    }
    create_response = client.post("/users/", json=user_data)
    print(f"Create user response status: {create_response.status_code}")
    print(f"Create user response content: {create_response.json()}")
    assert create_response.status_code == 200, "Failed to create test user"
    created_user_id = create_response.json()["id"]

    # Try to read the newly created user (this should fail as it's not the same user or an admin)
    response = client.get(f"/users/{created_user_id}", headers={"Authorization": f"Bearer {user_token}"})
    print(f"Read other user response status: {response.status_code}")
    print(f"Read other user response content: {response.json()}")
    assert response.status_code == 403, "Non-admin user should not be able to read other user's details"

    # Try to read the authenticated user's own details (this should succeed)
    me_response = client.get("/users/me", headers={"Authorization": f"Bearer {user_token}"})
    print(f"Read own user response status: {me_response.status_code}")
    print(f"Read own user response content: {me_response.json()}")
    assert me_response.status_code == 200, f"Failed to read own user details. Status: {me_response.status_code}, Content: {me_response.content}"

    user_data = me_response.json()
    assert "id" in user_data, "User data should contain 'id'"
    assert "username" in user_data, "User data should contain 'username'"
    assert "email" in user_data, "User data should contain 'email'"
    assert "role" in user_data, "User data should contain 'role'"

    # Try to read a non-existent user
    non_existent_response = client.get("/users/9999", headers={"Authorization": f"Bearer {user_token}"})
    print(f"Read non-existent user response status: {non_existent_response.status_code}")
    print(f"Read non-existent user response content: {non_existent_response.json()}")
    assert non_existent_response.status_code == 404, "Reading non-existent user should return 404"

    print("--- read_user test completed ---")

def test_create_task_with_invalid_data(client, user_token):
    invalid_task_data = {
        "title": "",  # Empty title
        "description": "This is an invalid task",
        "status": "Invalid Status",
        "due_date": "invalid_date",
        "task_type": "invalid_type"
    }
    response = client.post("/tasks/", json=invalid_task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 422, f"Expected validation error. Response: {response.content}"

def test_update_task_not_found(client, user_token):
    update_data = {
        "title": "Updated Task",
        "status": "In Progress",
        "task_type": TaskType.TASK
    }
    response = client.put("/tasks/99999", json=update_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 404, f"Expected not found error. Response: {response.content}"

def test_delete_task_not_found(client, user_token):
    response = client.delete("/tasks/99999", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 404, f"Expected not found error. Response: {response.content}"

def test_create_task_with_custom_fields(client, user_token):
    task_data = {
        "title": "Task with Custom Fields",
        "description": "This task has custom fields",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK,
        "custom_fields": [
            {"name": "Priority", "field_type": "string", "value": "High"},
            {"name": "Effort", "field_type": "number", "value": 5}
        ]
    }
    response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to create task with custom fields. Response: {response.content}"
    assert len(response.json()["custom_fields"]) == 2

def test_update_task_with_custom_fields(client, user_token):
    # First, create a task with custom fields
    task_data = {
        "title": "Task to Update Custom Fields",
        "description": "This task will have its custom fields updated",
        "status": "Todo",
        "due_date": (datetime.now() + timedelta(days=1)).isoformat(),
        "task_type": TaskType.TASK,
        "custom_fields": [
            {"name": "Priority", "field_type": "string", "value": "Medium"}
        ]
    }
    create_response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Now, update the task and its custom fields
    update_data = {
        "title": "Updated Task with Custom Fields",
        "status": "In Progress",
        "task_type": TaskType.TASK,
        "custom_fields": [
            {"name": "Priority", "field_type": "string", "value": "High"},
            {"name": "Deadline", "field_type": "date", "value": "2023-12-31"}
        ]
    }
    response = client.put(f"/tasks/{task_id}", json=update_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 200, f"Failed to update task with custom fields. Response: {response.content}"
    assert len(response.json()["custom_fields"]) == 2
    assert response.json()["custom_fields"][0]["value"] == "High"

def test_create_task_hierarchy(client, user_token):
    # Create a project
    project_data = {
        "title": "Project Task",
        "description": "This is a project",
        "status": "In Progress",
        "task_type": TaskType.PROJECT
    }
    project_response = client.post("/tasks/", json=project_data, headers={"Authorization": f"Bearer {user_token}"})
    assert project_response.status_code == 200
    project_id = project_response.json()["id"]

    # Create an epic under the project
    epic_data = {
        "title": "Epic Task",
        "description": "This is an epic",
        "status": "Todo",
        "task_type": TaskType.EPIC,
        "parent_id": project_id
    }
    epic_response = client.post("/tasks/", json=epic_data, headers={"Authorization": f"Bearer {user_token}"})
    assert epic_response.status_code == 200
    epic_id = epic_response.json()["id"]

    # Create a story under the epic
    story_data = {
        "title": "Story Task",
        "description": "This is a story",
        "status": "Todo",
        "task_type": TaskType.STORY,
        "parent_id": epic_id
    }
    story_response = client.post("/tasks/", json=story_data, headers={"Authorization": f"Bearer {user_token}"})
    assert story_response.status_code == 200

    # Verify the hierarchy
    hierarchy_response = client.get("/tasks/hierarchy/", headers={"Authorization": f"Bearer {user_token}"})
    assert hierarchy_response.status_code == 200
    hierarchy = hierarchy_response.json()
    assert any(task["id"] == project_id for task in hierarchy)
    project = next(task for task in hierarchy if task["id"] == project_id)
    assert any(child["id"] == epic_id for child in project["children"])

def test_invalid_task_hierarchy(client, user_token):
    # Try to create a project with a non-existent parent
    invalid_project_data = {
        "title": "Invalid Project Task",
        "description": "This project shouldn't have a parent",
        "status": "In Progress",
        "task_type": TaskType.PROJECT,
        "parent_id": 99999  # This should be invalid
    }
    response = client.post("/tasks/", json=invalid_project_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 400, f"Expected bad request error. Response: {response.content}"
    assert "Projects cannot have a parent" in response.json()["detail"]

    # Try to create a project with an existing parent
    # First, create a task to use as a parent
    parent_task_data = {
        "title": "Parent Task",
        "description": "This is a parent task",
        "status": "In Progress",
        "task_type": TaskType.TASK
    }
    parent_response = client.post("/tasks/", json=parent_task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert parent_response.status_code == 200
    parent_id = parent_response.json()["id"]

    # Now try to create a project with this parent
    invalid_project_data["parent_id"] = parent_id
    response = client.post("/tasks/", json=invalid_project_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 400, f"Expected bad request error. Response: {response.content}"
    assert "Projects cannot have a parent" in response.json()["detail"]

    # Try to create a subtask without a parent
    invalid_subtask_data = {
        "title": "Invalid Subtask",
        "description": "This subtask should have a parent",
        "status": "Todo",
        "task_type": TaskType.SUBTASK
    }
    response = client.post("/tasks/", json=invalid_subtask_data, headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 400, f"Expected bad request error. Response: {response.content}"
    assert "Subtasks must have a parent" in response.json()["detail"]

def test_read_subtasks(client, user_token):
    # Create a parent task
    parent_task_data = {
        "title": "Parent Task for Subtasks",
        "description": "This task will have subtasks",
        "status": "In Progress",
        "task_type": TaskType.TASK
    }
    parent_response = client.post("/tasks/", json=parent_task_data, headers={"Authorization": f"Bearer {user_token}"})
    assert parent_response.status_code == 200
    parent_id = parent_response.json()["id"]

    # Create subtasks
    for i in range(3):
        subtask_data = {
            "title": f"Subtask {i+1}",
            "description": f"This is subtask {i+1}",
            "status": "Todo",
            "task_type": TaskType.SUBTASK,
            "parent_id": parent_id
        }
        response = client.post("/tasks/", json=subtask_data, headers={"Authorization": f"Bearer {user_token}"})
        assert response.status_code == 200

    # Read subtasks
    subtasks_response = client.get(f"/tasks/{parent_id}/subtasks/", headers={"Authorization": f"Bearer {user_token}"})
    assert subtasks_response.status_code == 200
    subtasks = subtasks_response.json()
    assert len(subtasks) == 3

def test_user_cannot_access_other_users_tasks(client):
    # Create two users
    user1_data = {
        "username": "user1",
        "email": "user1@example.com",
        "password": "password1",
        "role": UserRole.USER
    }
    user2_data = {
        "username": "user2",
        "email": "user2@example.com",
        "password": "password2",
        "role": UserRole.USER
    }
    client.post("/users/", json=user1_data)
    client.post("/users/", json=user2_data)

    # Login as user1 and create a task
    user1_token_response = client.post("/token", data={"username": "user1", "password": "password1"})
    user1_token = user1_token_response.json()["access_token"]
    
    task_data = {
        "title": "User1's Task",
        "description": "This task belongs to user1",
        "status": "Todo",
        "task_type": TaskType.TASK
    }
    task_response = client.post("/tasks/", json=task_data, headers={"Authorization": f"Bearer {user1_token}"})
    assert task_response.status_code == 200
    task_id = task_response.json()["id"]

    # Login as user2 and try to access user1's task
    user2_token_response = client.post("/token", data={"username": "user2", "password": "password2"})
    user2_token = user2_token_response.json()["access_token"]
    
    response = client.get(f"/tasks/{task_id}", headers={"Authorization": f"Bearer {user2_token}"})
    assert response.status_code == 404, f"User2 should not be able to access User1's task. Response: {response.content}"

if __name__ == "__main__":
    pytest.main([__file__])