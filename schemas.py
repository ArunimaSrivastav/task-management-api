from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional, List, Any
from enum import Enum

class TaskType(str, Enum):
    PROJECT = "project"
    EPIC = "epic"
    STORY = "story"
    TASK = "task"
    SUBTASK = "subtask"
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: UserRole

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        from_attributes = True

class CustomFieldCreate(BaseModel):
    name: str
    field_type: str
    value: Any

class CustomField(CustomFieldCreate):
    id: int
    task_id: int

    class Config:
        from_attributes = True

class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str
    due_date: Optional[datetime] = None
    task_type: TaskType
    parent_id: Optional[int] = None

class TaskCreate(TaskBase):
    task_type: TaskType
    custom_fields: Optional[List[CustomFieldCreate]] = None

class TaskUpdate(TaskBase):
    custom_fields: Optional[List[CustomFieldCreate]] = None

class Task(TaskBase):
    id: int
    user_id: int
    custom_fields: List[CustomField] = []

    class Config:
        from_attributes = True

class TaskWithChildren(Task):
    children: List['TaskWithChildren'] = []

TaskWithChildren.model_rebuild()

class CategoryCreate(BaseModel):
    name: str

class Category(CategoryCreate):
    id: int

    class Config:
        from_attributes = True

class LabelCreate(BaseModel):
    name: str

class Label(LabelCreate):
    id: int

    class Config:
        from_attributes = True

class TaskWithRelations(Task):
    category: Optional[Category] = None
    labels: List[Label] = Field(default_factory=list)

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    username: str
    role: UserRole