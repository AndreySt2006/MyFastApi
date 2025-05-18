from fastapi.testclient import TestClient
import pytest
import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import (
    app, Base, get_db, User, Task, TaskStatus, TaskResponse,
    get_password_hash, verify_password, create_access_token,
    SECRET_KEY, ALGORITHM
)

TEST_DATABASE_URL = "sqlite:///./test_tasks.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    global db
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def setup_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        test_user = User(username="testuser", hashed_password=get_password_hash("testpassword"))
        db.add(test_user)
        db.commit()
        db.refresh(test_user)
        test_task = Task(
            title="Test Task", description="This is a test task",
            priority=1, status=TaskStatus.pending, owner_id=test_user.id
        )
        db.add(test_task)
        db.commit()
    finally:
        db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client_with_db(setup_database):
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client


def get_token(client):
    response = client.post("/token", data={"username": "testuser", "password": "testpassword"})
    return response.json().get("access_token")


class TestAuth:
    def test_register_user(self, client_with_db):
        response = client_with_db.post("/register/", params={"username": "newuser", "password": "newpassword"})
        assert response.status_code == 200
        assert response.json() == {"message": "User registered"}

    def test_login_success(self, client_with_db):
        response = client_with_db.post("/token", data={"username": "testuser", "password": "testpassword"})
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"

    def test_login_invalid_credentials(self, client_with_db):
        response = client_with_db.post("/token", data={"username": "testuser", "password": "wrongpassword"})
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid credentials"}

    def test_login_nonexistent_user(self, client_with_db):
        response = client_with_db.post("/token", data={"username": "nonexistentuser", "password": "testpassword"})
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid credentials"}


class TestToken:
    def test_expired_token(self, client_with_db):
        expired_token = jwt.encode(
            {"sub": "testuser", "exp": datetime.utcnow() - timedelta(seconds=10)},
            SECRET_KEY, algorithm=ALGORITHM
        )
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {expired_token}"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Token has expired"

    def test_invalid_token(self, client_with_db):
        response = client_with_db.get("/tasks/", headers={"Authorization": "Bearer abc.def.ghi"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid token"

    def test_token_with_invalid_username(self, client_with_db):
        invalid_token = jwt.encode(
            {"sub": "nonexistent_user", "exp": datetime.utcnow() + timedelta(minutes=30)},
            SECRET_KEY, algorithm=ALGORITHM
        )
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {invalid_token}"})
        assert response.status_code == 401
        assert response.json()["detail"] == "User not found"

    def test_create_access_token(self):
        token = create_access_token({"sub": "testuser"})
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload.get("sub") == "testuser"
        assert "exp" in payload

        token = create_access_token({"sub": "testuser"}, expires_delta=timedelta(minutes=5))
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload.get("sub") == "testuser"
        assert "exp" in payload


class TestTaskOperations:
    def test_create_task(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.post(
            "/tasks/",
            params={"title": "New Task", "description": "This is a new task", "priority": 2},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        task = response.json()[0]
        assert task["title"] == "New Task"
        assert task["description"] == "This is a new task"
        assert task["priority"] == 2
        assert task["status"] == "pending"
        assert response.json()[1]["message"] == "Successfully updated task"

    def test_create_task_unauthorized(self, client_with_db):
        response = client_with_db.post(
            "/tasks/",
            params={"title": "New Task", "description": "This is a new task", "priority": 2}
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Not authenticated"}

    def test_get_tasks(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        tasks = response.json()
        assert len(tasks) >= 1
        assert tasks[0]["title"] == "Test Task"
        assert tasks[0]["status"] == "pending"

    def test_update_task(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        task_id = response.json()[0]["id"]

        response = client_with_db.put(
            f"/tasks/{task_id}",
            params={
                "title": "Updated Task", "description": "This task has been updated",
                "status": "in_progress", "priority": 3
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        task = response.json()[0]
        assert task["title"] == "Updated Task"
        assert task["status"] == "in_progress"
        assert response.json()[1]["message"] == "Successfully updated task"

    def test_delete_task(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        task_id = response.json()[0]["id"]
        response = client_with_db.delete(f"/tasks/{task_id}", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json() == {"message": "Task deleted"}
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        assert task_id not in [task["id"] for task in response.json()]


class TestSearchAndFilter:
    def test_get_tasks_with_search(self, client_with_db):
        token = get_token(client_with_db)
        client_with_db.post(
            "/tasks/",
            params={"title": "Another Task", "description": "This task shouldn't match our search", "priority": 1},
            headers={"Authorization": f"Bearer {token}"}
        )
        response = client_with_db.get(
            "/tasks/",
            params={"search": "test"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        tasks = response.json()
        assert len(tasks) >= 1
        assert all("test" in task["title"].lower() or "test" in task["description"].lower() for task in tasks)

    def test_get_tasks_with_sorting(self, client_with_db):
        token = get_token(client_with_db)
        client_with_db.post(
            "/tasks/",
            params={"title": "A Task", "description": "This is task A", "priority": 3},
            headers={"Authorization": f"Bearer {token}"}
        )
        response = client_with_db.get(
            "/tasks/",
            params={"sort_by": "title"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()[0]["title"] == "A Task"

    def test_get_tasks_with_top_n(self, client_with_db):
        token = get_token(client_with_db)
        client_with_db.post(
            "/tasks/",
            params={"title": "High Priority Task", "description": "High priority", "priority": 5},
            headers={"Authorization": f"Bearer {token}"}
        )
        response = client_with_db.get(
            "/tasks/",
            params={"top_n": 1},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        tasks = response.json()
        assert len(tasks) == 1
        assert tasks[0]["priority"] == 5

    def test_get_tasks_combined_filters(self, client_with_db):
        token = get_token(client_with_db)
        client_with_db.post(
            "/tasks/",
            params={"title": "Combo Task", "description": "Special", "priority": 9},
            headers={"Authorization": f"Bearer {token}"}
        )
        response = client_with_db.get(
            "/tasks/",
            params={"sort_by": "title", "top_n": 1, "search": "combo"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        tasks = response.json()
        assert len(tasks) == 1
        assert tasks[0]["title"] == "Combo Task"


class TestErrorsAndEdgeCases:
    def test_update_nonexistent_task(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.put(
            "/tasks/9999",
            params={
                "title": "Updated Task", "description": "This task has been updated",
                "status": "in_progress", "priority": 3
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 404
        assert response.json() == {"detail": "Task not found"}

    def test_delete_nonexistent_task(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.delete("/tasks/9999", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 404
        assert response.json() == {"detail": "Task not found"}

    def test_update_task_invalid_status(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        task_id = response.json()[0]["id"]
        response = client_with_db.put(
            f"/tasks/{task_id}",
            params={
                "title": "Updated Task", "description": "This task has been updated",
                "status": "invalid_status", "priority": 3
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 422
        assert "detail" in response.json()

    def test_create_task_with_long_strings(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.post(
            "/tasks/",
            params={
                "title": "X" * 100,
                "description": "Y" * 1000,
                "priority": 2
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        task = response.json()[0]
        assert len(task["title"]) == 100
        assert len(task["description"]) == 1000

    def test_update_task_with_empty_title(self, client_with_db):
        token = get_token(client_with_db)
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        task_id = response.json()[0]["id"]
        response = client_with_db.put(
            f"/tasks/{task_id}",
            params={
                "title": "", "description": "This task has an empty title",
                "status": "pending", "priority": 3
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()[0]["title"] == ""

    def test_get_tasks_empty_database(self, client_with_db):
        client_with_db.post("/register/", params={"username": "emptyuser", "password": "password123"})
        response = client_with_db.post("/token", data={"username": "emptyuser", "password": "password123"})
        token = response.json()["access_token"]
        response = client_with_db.get("/tasks/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert response.json() == []


class TestModelsAndUtils:
    def test_password_hash_functions(self):
        password = "testpassword"
        hashed = get_password_hash(password)
        assert hashed != password
        assert verify_password(password, hashed) is True
        assert verify_password("wrongpassword", hashed) is False

    def test_task_status_enum_values(self):
        assert TaskStatus.pending.value == "pending"
        assert TaskStatus.in_progress.value == "in_progress"
        assert TaskStatus.completed.value == "completed"
        assert len(list(TaskStatus)) == 3

    def test_task_response_model(self):
        task = Task(
            id=1, title="Test Task", description="Test Description",
            status=TaskStatus.pending, priority=1,
            created_at=datetime.utcnow(), owner_id=1
        )
        response = TaskResponse.model_validate(task)
        assert response.id == task.id
        assert response.title == task.title
        assert response.status == task.status

    def test_user_model_relationship(self, client_with_db, setup_database):
        db = next(override_get_db())
        user = db.query(User).filter(User.username == "testuser").first()
        assert user is not None
        assert len(user.tasks) > 0
        assert user.tasks[0].title == "Test Task"

