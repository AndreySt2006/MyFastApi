import pytest
import sys
import os
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import jwt
from datetime import datetime, timedelta
from unittest.mock import MagicMock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (
    app,
    get_db,
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
    Base,
    User,
    Task,
    TaskStatus,
    SECRET_KEY,
    ALGORITHM
)

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    global db
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def test_user(setup_db):
    db = TestingSessionLocal()
    hashed_password = get_password_hash("testpassword")
    user = User(username="testuser", hashed_password=hashed_password)
    db.add(user)
    db.commit()
    user_from_db = db.query(User).filter(User.username == "testuser").first()
    db.close()
    return user_from_db

def test_password_hashing():
    password = "testpassword"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrongpassword", hashed)

def test_create_access_token():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert decoded["sub"] == "testuser"
    assert "exp" in decoded

def test_create_access_token_with_expiry():
    data = {"sub": "testuser"}
    expires = timedelta(minutes=30)
    token = create_access_token(data, expires)
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert decoded["sub"] == "testuser"
    expiry_time = datetime.utcfromtimestamp(decoded["exp"])
    expected_expiry = datetime.utcnow() + expires
    difference = abs((expiry_time - expected_expiry).total_seconds())
    assert difference < 10

def test_get_current_user_valid_token():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    mock_db = MagicMock()
    mock_user = MagicMock(spec=User)
    mock_user.username = "testuser"
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user
    user = get_current_user(db=mock_db, token=token)
    assert user.username == "testuser"
    mock_db.query.assert_called_once()

def test_get_current_user_invalid_token():
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(db=MagicMock(), token="invalid_token")
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"

def test_get_current_user_expired_token():
    data = {"sub": "testuser", "exp": datetime.utcnow() - timedelta(minutes=1)}
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(db=MagicMock(), token=token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token has expired"

def test_task_status_enum():
    assert TaskStatus.pending == "pending"
    assert TaskStatus.in_progress == "in_progress"
    assert TaskStatus.completed == "completed"
    db = TestingSessionLocal()
    Base.metadata.create_all(bind=engine)
    user = User(username="statustest", hashed_password="dummy")
    db.add(user)
    db.commit()
    task = Task(
        title="Test Task",
        description="Test Description",
        status=TaskStatus.pending,
        owner_id=user.id
    )
    db.add(task)
    db.commit()
    fetched_task = db.query(Task).filter(Task.title == "Test Task").first()
    assert fetched_task.status == TaskStatus.pending
    db.query(Task).delete()
    db.query(User).delete()
    db.commit()
    db.close()
    Base.metadata.drop_all(bind=engine)

def test_user_model(setup_db):
    db = TestingSessionLocal()
    user = User(username="modeltest", hashed_password="test_hash")
    db.add(user)
    db.commit()
    fetched_user = db.query(User).filter(User.username == "modeltest").first()
    assert fetched_user.username == "modeltest"
    assert fetched_user.hashed_password == "test_hash"
    task = Task(
        title="User Task",
        description="Testing user relationship",
        owner_id=fetched_user.id
    )
    db.add(task)
    db.commit()
    db.refresh(fetched_user)
    assert len(fetched_user.tasks) == 1
    assert fetched_user.tasks[0].title == "User Task"
    db.close()

def test_task_model(setup_db):
    db = TestingSessionLocal()
    user = User(username="taskmodeltest", hashed_password="test_hash")
    db.add(user)
    db.commit()
    created_time = datetime.utcnow()
    task = Task(
        title="Task Model Test",
        description="Testing task model",
        status=TaskStatus.in_progress,
        priority=3,
        owner_id=user.id
    )
    db.add(task)
    db.commit()
    fetched_task = db.query(Task).filter(Task.title == "Task Model Test").first()
    assert fetched_task.title == "Task Model Test"
    assert fetched_task.description == "Testing task model"
    assert fetched_task.status == TaskStatus.in_progress
    assert fetched_task.priority == 3
    assert abs((fetched_task.created_at - created_time).total_seconds()) < 10
    assert fetched_task.owner.username == "taskmodeltest"
    db.close()

def test_get_db():
    db = next(get_db())
    assert db is not None
    db.close()