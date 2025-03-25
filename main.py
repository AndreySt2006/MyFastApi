from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Enum, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import List, Optional
import enum
import jwt
from pydantic import BaseModel

DATABASE_URL = "sqlite:///./tasks.db"
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class TaskStatus(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    tasks = relationship("Task", back_populates="owner")

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, index=True)
    status = Column(Enum(TaskStatus), default=TaskStatus.pending)
    priority = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="tasks")

class TaskResponse(BaseModel):
    id: int
    title: str
    description: str
    status: TaskStatus
    priority: int
    created_at: datetime
    owner_id: int

    class Config:
        from_attributes = True

Base.metadata.create_all(bind=engine)

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

app = FastAPI()

@app.post("/register/")
def register(username: str, password: str, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(password)
    user = User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    return {"message": "User registered"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    print(f"Login attempt: {form_data.username}")
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user:
        print("User not found")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    print(f"Stored hashed password: {user.hashed_password}")

    if not verify_password(form_data.password, user.hashed_password):
        print("Password does not match")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/tasks/")
def create_task(title: str, description: str, priority: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    task = Task(title=title, description=description, priority=priority, owner_id=user.id)
    db.add(task)
    db.commit()
    return task, {"message": "Successfully updated task"}

@app.get("/tasks/", response_model=List[TaskResponse])
def get_tasks(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    sort_by: Optional[str] = Query(None, enum=["title", "status", "created_at"]),
    top_n: Optional[int] = None,
    search: Optional[str] = None
):
    tasks = db.query(Task).filter(Task.owner_id == user.id)
    if search:
        tasks = tasks.filter((Task.title.contains(search)) | (Task.description.contains(search)))
    if sort_by:
        tasks = tasks.order_by(getattr(Task, sort_by))
    if top_n:
        tasks = tasks.order_by(Task.priority.desc()).limit(top_n)
    return tasks.all()

@app.put("/tasks/{task_id}")
def update_task(task_id: int, title: str, description: str, status: TaskStatus, priority: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    task = db.query(Task).filter(Task.id == task_id, Task.owner_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    task.title = title
    task.description = description
    task.status = status
    task.priority = priority
    db.commit()
    return task, {"message": "Successfully updated task"}

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    task = db.query(Task).filter(Task.id == task_id, Task.owner_id == user.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete(task)
    db.commit()
    return {"message": "Task deleted"}