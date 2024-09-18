from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from typing import List, Optional
from fastapi.responses import JSONResponse
import logging

import models
import schemas
from schemas import *
from database import engine, get_db
from dependencies import get_current_user, admin_required
from auth import create_access_token, verify_token, hash_password, verify_password

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

def check_valid_parent(parent_task: models.Task, new_task_type: models.TaskType):
    if parent_task.task_type == models.TaskType.SUBTASK:
        raise HTTPException(status_code=400, detail="Subtasks cannot have children")
    if new_task_type == models.TaskType.PROJECT:
        raise HTTPException(status_code=400, detail="Projects cannot have a parent")
    if parent_task.task_type == models.TaskType.TASK and new_task_type != models.TaskType.SUBTASK:
        raise HTTPException(status_code=400, detail="Tasks can only have subtasks as children")
    if parent_task.task_type == models.TaskType.STORY and new_task_type not in [models.TaskType.TASK, models.TaskType.SUBTASK]:
        raise HTTPException(status_code=400, detail="Stories can only have tasks or subtasks as children")
    if parent_task.task_type == models.TaskType.EPIC and new_task_type not in [models.TaskType.STORY, models.TaskType.TASK]:
        raise HTTPException(status_code=400, detail="Epics can only have stories or tasks as children")

def validate_task_hierarchy(task: schemas.TaskCreate, parent_task: Optional[models.Task] = None):
    if task.task_type == models.TaskType.PROJECT and parent_task is not None:
        raise HTTPException(status_code=400, detail="Projects cannot have a parent")
    if task.task_type == models.TaskType.SUBTASK and parent_task is None:
        raise HTTPException(status_code=400, detail="Subtasks must have a parent")
    if task.task_type == models.TaskType.EPIC and parent_task is not None and parent_task.task_type != models.TaskType.PROJECT:
        raise HTTPException(status_code=400, detail="Epics can only be children of projects")
    if task.task_type == models.TaskType.STORY and parent_task is not None and parent_task.task_type not in [models.TaskType.PROJECT, models.TaskType.EPIC]:
        raise HTTPException(status_code=400, detail="Stories can only be children of projects or epics")
    
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = hash_password(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role  # Ensure the role is set correctly
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=schemas.TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    logging.info(f"Current user: {current_user}")
    logging.info(f"Current user dict: {current_user.__dict__}")
    return current_user


@app.get("/users/", response_model=List[schemas.User])
def read_users(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(
    user_id: int, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user.role != schemas.UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return db_user

@app.post("/tasks/", response_model=schemas.Task)
def create_task(
    task: schemas.TaskCreate, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    # First, validate the task hierarchy
    if task.task_type == models.TaskType.PROJECT and task.parent_id is not None:
        raise HTTPException(status_code=400, detail="Projects cannot have a parent")
    if task.task_type == models.TaskType.SUBTASK and task.parent_id is None:
        raise HTTPException(status_code=400, detail="Subtasks must have a parent")

    # If a parent_id is provided, check if it exists and belongs to the current user
    if task.parent_id:
        parent_task = db.query(models.Task).filter(
            models.Task.id == task.parent_id, 
            models.Task.user_id == current_user.id
        ).first()
        if not parent_task:
            raise HTTPException(status_code=404, detail="Parent task not found")
        
        # Validate the parent-child relationship
        if parent_task.task_type == models.TaskType.SUBTASK:
            raise HTTPException(status_code=400, detail="Subtasks cannot have children")
        if parent_task.task_type == models.TaskType.TASK and task.task_type != models.TaskType.SUBTASK:
            raise HTTPException(status_code=400, detail="Tasks can only have subtasks as children")
        if parent_task.task_type == models.TaskType.STORY and task.task_type not in [models.TaskType.TASK, models.TaskType.SUBTASK]:
            raise HTTPException(status_code=400, detail="Stories can only have tasks or subtasks as children")
        if parent_task.task_type == models.TaskType.EPIC and task.task_type not in [models.TaskType.STORY, models.TaskType.TASK]:
            raise HTTPException(status_code=400, detail="Epics can only have stories or tasks as children")

    # Create the task object
    db_task = models.Task(**task.model_dump(exclude={"custom_fields"}), user_id=current_user.id)
    
    # Add and commit the task
    db.add(db_task)
    db.commit()
    db.refresh(db_task)

    # Handle custom fields if any
    if task.custom_fields:
        custom_fields = [models.CustomField(**cf.model_dump(), task_id=db_task.id) for cf in task.custom_fields]
        db.add_all(custom_fields)
        db.commit()
        db.refresh(db_task)

    return schemas.Task.from_orm(db_task)

@app.get("/tasks/{task_id}", response_model=schemas.Task)
def read_task(task_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@app.get("/tasks/", response_model=List[schemas.Task])
def read_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    tasks = db.query(models.Task).filter(models.Task.user_id == current_user.id).offset(skip).limit(limit).all()
    return tasks

@app.put("/tasks/{task_id}", response_model=schemas.Task)
def update_task(
    task_id: int, 
    task: schemas.TaskUpdate, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    db_task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if db_task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    for key, value in task.model_dump(exclude={"custom_fields"}).items():
        setattr(db_task, key, value)
    
    if task.custom_fields is not None:
        # Remove existing custom fields
        db.query(models.CustomField).filter(models.CustomField.task_id == db_task.id).delete()
        
        # Add new custom fields
        for custom_field in task.custom_fields:
            db_custom_field = models.CustomField(**custom_field.model_dump(), task_id=db_task.id)
            db.add(db_custom_field)
    
    db.commit()
    db.refresh(db_task)
    return db_task

@app.delete("/tasks/{task_id}", response_model=schemas.Task)
def delete_task(
    task_id: int, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    db_task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if db_task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete(db_task)
    db.commit()
    return db_task

@app.post("/tasks/{task_id}/custom-fields/", response_model=schemas.CustomField)
def create_custom_field(
    task_id: int,
    custom_field: schemas.CustomFieldCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    db_custom_field = models.CustomField(**custom_field.model_dump(), task_id=task.id)
    db.add(db_custom_field)
    db.commit()
    db.refresh(db_custom_field)
    return db_custom_field

@app.get("/tasks/{task_id}/custom-fields/", response_model=List[schemas.CustomField])
def read_custom_fields(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task.custom_fields

@app.put("/tasks/{task_id}/custom-fields/{field_id}", response_model=schemas.CustomField)
def update_custom_field(
    task_id: int,
    field_id: int,
    custom_field: schemas.CustomFieldCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    db_custom_field = db.query(models.CustomField).filter(models.CustomField.id == field_id, models.CustomField.task_id == task.id).first()
    if db_custom_field is None:
        raise HTTPException(status_code=404, detail="Custom field not found")
    
    for key, value in custom_field.model_dump().items():
        setattr(db_custom_field, key, value)
    
    db.commit()
    db.refresh(db_custom_field)
    return db_custom_field

@app.delete("/tasks/{task_id}/custom-fields/{field_id}", response_model=schemas.CustomField)
def delete_custom_field(
    task_id: int,
    field_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    
    db_custom_field = db.query(models.CustomField).filter(models.CustomField.id == field_id, models.CustomField.task_id == task.id).first()
    if db_custom_field is None:
        raise HTTPException(status_code=404, detail="Custom field not found")
    
    db.delete(db_custom_field)
    db.commit()
    return db_custom_field

@app.post("/tasks/{parent_id}/subtasks/", response_model=schemas.Task)
def create_subtask(
    parent_id: int,
    task: schemas.TaskCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    parent_task = db.query(models.Task).filter(models.Task.id == parent_id, models.Task.user_id == current_user.id).first()
    if parent_task is None:
        raise HTTPException(status_code=404, detail="Parent task not found")
    
    db_task = models.Task(**task.model_dump(exclude={"custom_fields"}), user_id=current_user.id, parent_id=parent_id)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    
    if task.custom_fields:
        for custom_field in task.custom_fields:
            db_custom_field = models.CustomField(**custom_field.model_dump(), task_id=db_task.id)
            db.add(db_custom_field)
        db.commit()
        db.refresh(db_task)
    
    return db_task

@app.get("/tasks/{task_id}/subtasks/", response_model=List[schemas.Task])
def read_subtasks(
    task_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # First, verify that the parent task belongs to the current user
    parent_task = db.query(models.Task).filter(models.Task.id == task_id, models.Task.user_id == current_user.id).first()
    if parent_task is None:
        raise HTTPException(status_code=404, detail="Parent task not found")

    subtasks = db.query(models.Task).filter(
        models.Task.parent_id == task_id,
        models.Task.user_id == current_user.id
    ).offset(skip).limit(limit).all()
    
    return subtasks

@app.get("/tasks/hierarchy/", response_model=List[schemas.TaskWithChildren])
def read_task_hierarchy(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    tasks = db.query(models.Task).filter(
        models.Task.user_id == current_user.id,
        models.Task.parent_id == None
    ).options(joinedload(models.Task.children)).offset(skip).limit(limit).all()
    
    return tasks

# Error Handlers
@app.exception_handler(IntegrityError)
async def integrity_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Database integrity error. This might be due to a duplicate entry."}
    )