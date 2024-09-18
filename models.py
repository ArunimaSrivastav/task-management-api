from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Table, Enum as SQLAlchemyEnum, JSON
from sqlalchemy.orm import relationship, declarative_base
from enum import Enum

from database import Base

class TaskType(str, Enum):
    PROJECT = "project"
    EPIC = "epic"
    STORY = "story"
    TASK = "task"
    SUBTASK = "subtask"

class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

task_label = Table('task_label', Base.metadata,
    Column('task_id', Integer, ForeignKey('tasks.id')),
    Column('label_id', Integer, ForeignKey('labels.id'))
)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SQLAlchemyEnum(UserRole), default=UserRole.USER)
    tasks = relationship("Task", back_populates="user")

class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    status = Column(String)
    due_date = Column(DateTime)
    user_id = Column(Integer, ForeignKey("users.id"))
    task_type = Column(SQLAlchemyEnum(TaskType), default=TaskType.TASK)
    parent_id = Column(Integer, ForeignKey("tasks.id"), nullable=True)

    user = relationship("User", back_populates="tasks")
    parent = relationship("Task", remote_side=[id], back_populates="children")
    children = relationship("Task", back_populates="parent")
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    category = relationship("Category", back_populates="tasks")
    labels = relationship("Label", secondary=task_label, back_populates="tasks")
    custom_fields = relationship("CustomField", back_populates="task", cascade="all, delete-orphan")

class CustomField(Base):
    __tablename__ = "custom_fields"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    field_type = Column(String)
    task_id = Column(Integer, ForeignKey("tasks.id"))
    value = Column(JSON)

    task = relationship("Task", back_populates="custom_fields")

class Category(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    tasks = relationship("Task", back_populates="category")

class Label(Base):
    __tablename__ = "labels"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    tasks = relationship("Task", secondary=task_label, back_populates="labels")