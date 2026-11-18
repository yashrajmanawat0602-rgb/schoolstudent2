import os
import zipfile
from pathlib import Path

FILES: dict[str, str] = {
    "backend/requirements.txt": r'''fastapi==0.115.5
uvicorn[standard]==0.32.1
sqlalchemy==2.0.36
psycopg[binary]==3.2.3
pydantic==2.10.2
pydantic-settings==2.6.1
email-validator==2.2.0
PyJWT==2.10.0
bcrypt==4.2.1
python-multipart==0.0.17
pytest==8.3.3
httpx==0.28.0
''',

    "backend/.env.example": r'''DATABASE_URL=postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/schoolconnect
AUTH_SECRET=REPLACE_WITH_32_BYTE_RANDOM_SECRET
ACCESS_TOKEN_EXPIRE_MINUTES=10080
CORS_ORIGINS=http://localhost:3000
''',

    "backend/app/__init__.py": "",
    "backend/app/core/__init__.py": "",
    "backend/app/models/__init__.py": "",
    "backend/app/schemas/__init__.py": "",
    "backend/app/routers/__init__.py": "",

    "backend/app/core/config.py": r'''from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./schoolconnect_dev.db"
    AUTH_SECRET: str = "dev-only-change-in-production-32bytes"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    CORS_ORIGINS: str = "http://localhost:3000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
''',

    "backend/app/core/database.py": r'''from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import settings

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
''',

    "backend/app/core/security.py": r'''from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
ALGORITHM = "HS256"


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(user_id: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user_id, "role": role, "exp": expire}
    return jwt.encode(payload, settings.AUTH_SECRET, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication session.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.AUTH_SECRET, algorithms=[ALGORITHM])
        user_id: str | None = payload.get("sub")
        if not user_id:
            raise credentials_exc
    except jwt.PyJWTError:
        raise credentials_exc

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user:
        raise credentials_exc
    return user
''',

    "backend/app/core/rbac.py": r'''from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import get_current_user
from app.models.models import (
    ClassRoom,
    Enrollment,
    ParentProfile,
    ParentStudentLink,
    Role,
    StudentProfile,
    TeacherClassSubject,
    TeacherProfile,
    User,
)


def require_roles(*allowed_roles: Role):
    def dependency(actor: User = Depends(get_current_user)) -> User:
        if actor.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return actor

    return dependency


def assert_can_access_student(db: Session, actor: User, student_id: str) -> None:
    if actor.role == Role.ADMIN:
        return

    if actor.role == Role.STUDENT:
        own = db.query(StudentProfile).filter(StudentProfile.user_id == actor.id).first()
        if not own or own.id != student_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Students may only access their own records.",
            )
        return

    if actor.role == Role.PARENT:
        link = (
            db.query(ParentStudentLink)
            .join(ParentProfile, ParentStudentLink.parent_id == ParentProfile.id)
            .filter(ParentProfile.user_id == actor.id, ParentStudentLink.student_id == student_id)
            .first()
        )
        if not link:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Child is not linked to your parent account.",
            )
        return

    if actor.role == Role.TEACHER:
        teacher = db.query(TeacherProfile).filter(TeacherProfile.user_id == actor.id).first()
        if not teacher:
            raise HTTPException(status_code=403, detail="Teacher profile missing.")

        enrolled_in_teacher_class = (
            db.query(Enrollment)
            .join(ClassRoom, Enrollment.class_room_id == ClassRoom.id)
            .outerjoin(TeacherClassSubject, TeacherClassSubject.class_room_id == ClassRoom.id)
            .filter(
                Enrollment.student_id == student_id,
                (ClassRoom.class_teacher_id == teacher.id)
                | (TeacherClassSubject.teacher_id == teacher.id),
            )
            .first()
        )
        if not enrolled_in_teacher_class:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Student is not in your assigned classes.",
            )


def assert_teacher_authorized(
    db: Session, actor: User, class_room_id: str, subject_id: str | None = None
) -> str:
    if actor.role == Role.ADMIN:
        return "ADMIN"
    if actor.role != Role.TEACHER:
        raise HTTPException(status_code=403, detail="Teacher or Admin role required.")

    teacher = db.query(TeacherProfile).filter(TeacherProfile.user_id == actor.id).first()
    if not teacher:
        raise HTTPException(status_code=403, detail="Teacher profile missing.")

    q = db.query(TeacherClassSubject).filter(
        TeacherClassSubject.teacher_id == teacher.id,
        TeacherClassSubject.class_room_id == class_room_id,
    )
    if subject_id:
        q = q.filter(TeacherClassSubject.subject_id == subject_id)

    is_assigned = q.first() is not None
    is_homeroom = (
        False
        if subject_id
        else db.query(ClassRoom)
        .filter(ClassRoom.id == class_room_id, ClassRoom.class_teacher_id == teacher.id)
        .first()
        is not None
    )

    if not is_assigned and not is_homeroom:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You are not assigned to this class or subject.",
        )
    return teacher.id
''',

    "backend/app/models/models.py": r'''import enum
import uuid
from datetime import date, datetime, timezone
from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    TEACHER = "TEACHER"
    PARENT = "PARENT"
    STUDENT = "STUDENT"


class AttendanceStatus(str, enum.Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    LATE = "LATE"
    EXCUSED = "EXCUSED"
    HOLIDAY = "HOLIDAY"


class Priority(str, enum.Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    URGENT = "URGENT"


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    teacher_profile: Mapped["TeacherProfile | None"] = relationship(back_populates="user", uselist=False)
    parent_profile: Mapped["ParentProfile | None"] = relationship(back_populates="user", uselist=False)
    student_profile: Mapped["StudentProfile | None"] = relationship(back_populates="user", uselist=False)


class TeacherProfile(Base):
    __tablename__ = "teacher_profiles"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    employee_code: Mapped[str] = mapped_column(String(50), unique=True)
    user: Mapped["User"] = relationship(back_populates="teacher_profile")


class ParentProfile(Base):
    __tablename__ = "parent_profiles"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    user: Mapped["User"] = relationship(back_populates="parent_profile")
    children_links: Mapped[list["ParentStudentLink"]] = relationship(back_populates="parent")


class StudentProfile(Base):
    __tablename__ = "student_profiles"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    student_code: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    user: Mapped["User"] = relationship(back_populates="student_profile")
    parent_links: Mapped[list["ParentStudentLink"]] = relationship(back_populates="student")
    enrollments: Mapped[list["Enrollment"]] = relationship(back_populates="student")


class ParentStudentLink(Base):
    __tablename__ = "parent_student_links"
    __table_args__ = (UniqueConstraint("parent_id", "student_id", name="uq_parent_student"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    parent_id: Mapped[str] = mapped_column(ForeignKey("parent_profiles.id", ondelete="CASCADE"), index=True)
    student_id: Mapped[str] = mapped_column(ForeignKey("student_profiles.id", ondelete="CASCADE"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(40), default="Parent")

    parent: Mapped["ParentProfile"] = relationship(back_populates="children_links")
    student: Mapped["StudentProfile"] = relationship(back_populates="parent_links")


class ClassRoom(Base):
    __tablename__ = "class_rooms"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    display_name: Mapped[str] = mapped_column(String(30), unique=True)
    class_teacher_id: Mapped[str | None] = mapped_column(ForeignKey("teacher_profiles.id"))


class Subject(Base):
    __tablename__ = "subjects"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    code: Mapped[str] = mapped_column(String(20), unique=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)


class TeacherClassSubject(Base):
    __tablename__ = "teacher_class_subjects"
    __table_args__ = (UniqueConstraint("teacher_id", "class_room_id", "subject_id", name="uq_tcs"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    teacher_id: Mapped[str] = mapped_column(ForeignKey("teacher_profiles.id", ondelete="CASCADE"))
    class_room_id: Mapped[str] = mapped_column(ForeignKey("class_rooms.id", ondelete="CASCADE"))
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"))


class Enrollment(Base):
    __tablename__ = "enrollments"
    __table_args__ = (UniqueConstraint("student_id", "class_room_id", name="uq_student_class"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    student_id: Mapped[str] = mapped_column(ForeignKey("student_profiles.id", ondelete="CASCADE"))
    class_room_id: Mapped[str] = mapped_column(ForeignKey("class_rooms.id", ondelete="CASCADE"))
    roll_number: Mapped[int] = mapped_column(Integer)

    student: Mapped["StudentProfile"] = relationship(back_populates="enrollments")
    class_room: Mapped["ClassRoom"] = relationship()


class Exam(Base):
    __tablename__ = "exams"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    start_date: Mapped[date] = mapped_column(Date)


class Mark(Base):
    __tablename__ = "marks"
    __table_args__ = (UniqueConstraint("student_id", "exam_id", "subject_id", name="uq_mark"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    student_id: Mapped[str] = mapped_column(ForeignKey("student_profiles.id", ondelete="CASCADE"), index=True)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id", ondelete="CASCADE"))
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id"))
    class_room_id: Mapped[str] = mapped_column(ForeignKey("class_rooms.id"))
    obtained_marks: Mapped[float] = mapped_column(Float, nullable=False)
    max_marks: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(5), nullable=False)
    remark: Mapped[str | None] = mapped_column(String(400))
    entered_by_teacher_id: Mapped[str] = mapped_column(ForeignKey("teacher_profiles.id"))

    subject: Mapped["Subject"] = relationship()
    exam: Mapped["Exam"] = relationship()


class Attendance(Base):
    __tablename__ = "attendance"
    __table_args__ = (UniqueConstraint("student_id", "date", name="uq_attendance_day"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    student_id: Mapped[str] = mapped_column(ForeignKey("student_profiles.id", ondelete="CASCADE"), index=True)
    class_room_id: Mapped[str] = mapped_column(ForeignKey("class_rooms.id"))
    date: Mapped[date] = mapped_column(Date, index=True)
    status: Mapped[AttendanceStatus] = mapped_column(Enum(AttendanceStatus), nullable=False)
    note: Mapped[str | None] = mapped_column(String(250))


class Homework(Base):
    __tablename__ = "homeworks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    class_room_id: Mapped[str] = mapped_column(ForeignKey("class_rooms.id"))
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id"))
    due_date: Mapped[date] = mapped_column(Date)
    priority: Mapped[Priority] = mapped_column(Enum(Priority), default=Priority.NORMAL)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    subject: Mapped["Subject"] = relationship()


class Notice(Base):
    __tablename__ = "notices"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text)
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    is_important: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(String(400))
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    actor_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(80))
    summary: Mapped[str] = mapped_column(String(400))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
''',

    "backend/app/schemas/schemas.py": r'''from datetime import date
from pydantic import BaseModel, EmailStr, Field, model_validator
from app.models.models import AttendanceStatus, Priority, Role


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    name: str
    redirect_to: str


class MarkEntryRequest(BaseModel):
    student_id: str
    exam_id: str
    subject_id: str
    class_room_id: str
    obtained_marks: float = Field(ge=0)
    max_marks: float = Field(gt=0)
    remark: str | None = Field(default=None, max_length=400)

    @model_validator(mode="after")
    def validate_bounds(self):
        if self.obtained_marks > self.max_marks:
            raise ValueError("Marks cannot exceed maximum marks")
        return self


class AttendanceItem(BaseModel):
    student_id: str
    status: AttendanceStatus
    note: str | None = Field(default=None, max_length=250)


class AttendanceBulkRequest(BaseModel):
    class_room_id: str
    date: date
    entries: list[AttendanceItem] = Field(min_length=1)


class HomeworkCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=5, max_length=3000)
    class_room_id: str
    subject_id: str
    due_date: date
    priority: Priority = Priority.NORMAL


def compute_grade(obtained: float, maximum: float) -> str:
    pct = (obtained / maximum) * 100 if maximum > 0 else 0
    if pct >= 90:
        return "A+"
    if pct >= 80:
        return "A"
    if pct >= 70:
        return "B+"
    if pct >= 60:
        return "B"
    if pct >= 50:
        return "C"
    if pct >= 35:
        return "D"
    return "F"
''',

    "backend/app/routers/auth.py": r'''from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import create_access_token, verify_password
from app.models.models import AuditLog, Role, User
from app.schemas.schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/api/auth", tags=["Auth"])

ROLE_REDIRECT = {
    Role.ADMIN: "/dashboard/admin",
    Role.TEACHER: "/dashboard/teacher",
    Role.PARENT: "/dashboard/parent",
    Role.STUDENT: "/dashboard/student",
}


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    db.add(AuditLog(actor_user_id=user.id, action="LOGIN_SUCCESS", summary=f"{user.name} signed in."))
    db.commit()

    token = create_access_token(user_id=user.id, role=user.role.value)
    return LoginResponse(
        access_token=token,
        role=user.role,
        name=user.name,
        redirect_to=ROLE_REDIRECT[user.role],
    )
''',

    "backend/app/routers/parent.py": r'''from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rbac import assert_can_access_student, require_roles
from app.models.models import (
    Attendance,
    AttendanceStatus,
    Homework,
    Mark,
    Notice,
    Notification,
    ParentProfile,
    ParentStudentLink,
    Role,
    StudentProfile,
    User,
)

router = APIRouter(prefix="/api/parent", tags=["Parent & Student"])


@router.get("/overview")
def get_parent_overview(
    student_id: str | None = Query(default=None),
    actor: User = Depends(require_roles(Role.PARENT, Role.STUDENT)),
    db: Session = Depends(get_db),
):
    children = []
    if actor.role == Role.PARENT:
        links = (
            db.query(ParentStudentLink)
            .join(ParentProfile, ParentStudentLink.parent_id == ParentProfile.id)
            .filter(ParentProfile.user_id == actor.id)
            .all()
        )
        for link in links:
            enr = link.student.enrollments[0] if link.student.enrollments else None
            children.append({
                "id": link.student.id,
                "student_code": link.student.student_code,
                "name": link.student.user.name,
                "class_display": enr.class_room.display_name if enr else "Unassigned",
                "class_room_id": enr.class_room_id if enr else "",
                "roll_number": enr.roll_number if enr else 0,
            })
    else:
        own = db.query(StudentProfile).filter(StudentProfile.user_id == actor.id).first()
        if own:
            enr = own.enrollments[0] if own.enrollments else None
            children.append({
                "id": own.id,
                "student_code": own.student_code,
                "name": own.user.name,
                "class_display": enr.class_room.display_name if enr else "Unassigned",
                "class_room_id": enr.class_room_id if enr else "",
                "roll_number": enr.roll_number if enr else 0,
            })

    if not children:
        return {"children": [], "active_child": None}

    target_id = student_id or children[0]["id"]
    assert_can_access_student(db, actor, target_id)
    active_child = next((c for c in children if c["id"] == target_id), children[0])

    marks = db.query(Mark).filter(Mark.student_id == target_id).all()
    attendance = (
        db.query(Attendance)
        .filter(Attendance.student_id == target_id)
        .order_by(Attendance.date.desc())
        .limit(60)
        .all()
    )
    homeworks = (
        db.query(Homework)
        .filter(Homework.class_room_id == active_child["class_room_id"])
        .order_by(Homework.due_date.asc())
        .all()
    )
    notices = db.query(Notice).order_by(Notice.is_pinned.desc(), Notice.created_at.desc()).limit(8).all()
    unread_count = (
        db.query(Notification)
        .filter(Notification.user_id == actor.id, Notification.is_read.is_(False))
        .count()
    )

    avg_rows = (
        db.query(Mark.subject_id, func.avg(Mark.obtained_marks).label("avg_score"))
        .filter(Mark.class_room_id == active_child["class_room_id"])
        .group_by(Mark.subject_id)
        .all()
    )
    class_averages = {row.subject_id: round(float(row.avg_score), 1) for row in avg_rows}

    total_days = sum(1 for a in attendance if a.status != AttendanceStatus.HOLIDAY)
    present_days = sum(1 for a in attendance if a.status in (AttendanceStatus.PRESENT, AttendanceStatus.LATE))
    pct = round((present_days / total_days) * 100) if total_days > 0 else 100

    return {
        "children": children,
        "active_child": active_child,
        "marks": [
            {
                "subject": m.subject.name,
                "exam": m.exam.name,
                "obtained_marks": m.obtained_marks,
                "max_marks": m.max_marks,
                "grade": m.grade,
                "remark": m.remark,
                "class_avg": class_averages.get(m.subject_id),
            }
            for m in marks
        ],
        "attendance": {
            "total_days": total_days,
            "present_days": present_days,
            "percentage": pct,
            "records": [{"date": str(a.date), "status": a.status.value} for a in attendance],
        },
        "homeworks": [
            {
                "id": h.id,
                "subject": h.subject.name,
                "title": h.title,
                "description": h.description,
                "due_date": str(h.due_date),
            }
            for h in homeworks
        ],
        "notices": [
            {"id": n.id, "title": n.title, "description": n.description, "is_pinned": n.is_pinned}
            for n in notices
        ],
        "unread_notifications": unread_count,
    }
''',

    "backend/app/routers/marks.py": r'''import csv
import io
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rbac import assert_teacher_authorized, require_roles
from app.models.models import AuditLog, Enrollment, Exam, Mark, Role, StudentProfile, Subject, User
from app.schemas.schemas import MarkEntryRequest, compute_grade

router = APIRouter(prefix="/api/marks", tags=["Marks"])


@router.post("/")
def save_mark(
    payload: MarkEntryRequest,
    actor: User = Depends(require_roles(Role.TEACHER, Role.ADMIN)),
    db: Session = Depends(get_db),
):
    teacher_id = assert_teacher_authorized(db, actor, payload.class_room_id, payload.subject_id)
    grade = compute_grade(payload.obtained_marks, payload.max_marks)

    existing = (
        db.query(Mark)
        .filter(
            Mark.student_id == payload.student_id,
            Mark.exam_id == payload.exam_id,
            Mark.subject_id == payload.subject_id,
        )
        .first()
    )
    if existing:
        existing.obtained_marks = payload.obtained_marks
        existing.max_marks = payload.max_marks
        existing.grade = grade
        existing.remark = payload.remark
    else:
        db.add(
            Mark(
                student_id=payload.student_id,
                exam_id=payload.exam_id,
                subject_id=payload.subject_id,
                class_room_id=payload.class_room_id,
                obtained_marks=payload.obtained_marks,
                max_marks=payload.max_marks,
                grade=grade,
                remark=payload.remark,
                entered_by_teacher_id=teacher_id,
            )
        )

    db.add(AuditLog(actor_user_id=actor.id, action="UPSERT_MARK", summary=f"{actor.name} saved mark for {payload.student_id}."))
    db.commit()
    return {"status": "saved", "grade": grade}


@router.post("/import-csv")
async def import_marks_csv(
    class_room_id: str = Form(...),
    file: UploadFile = File(...),
    actor: User = Depends(require_roles(Role.TEACHER, Role.ADMIN)),
    db: Session = Depends(get_db),
):
    teacher_id = assert_teacher_authorized(db, actor, class_room_id)
    raw_bytes = await file.read()
    reader = csv.DictReader(io.StringIO(raw_bytes.decode("utf-8-sig")))

    errors: list[str] = []
    seen_keys: set[tuple[str, str, str]] = set()
    to_insert: list[Mark] = []

    students = {
        s.student_code: s
        for s in db.query(StudentProfile)
        .join(Enrollment, Enrollment.student_id == StudentProfile.id)
        .filter(Enrollment.class_room_id == class_room_id)
        .all()
    }
    subjects = {s.name.lower(): s for s in db.query(Subject).all()}
    exams = {e.name.lower(): e for e in db.query(Exam).all()}

    for row_idx, row in enumerate(reader, start=2):
        code = (row.get("Student ID") or "").strip()
        sub_name = (row.get("Subject") or "").strip()
        exam_name = (row.get("Exam") or "").strip()

        try:
            obtained = float(row.get("Marks") or "")
            maximum = float(row.get("Max Marks") or "")
        except ValueError:
            errors.append(f"Row {row_idx}: ❌ Marks and Max Marks must be valid numbers")
            continue

        if obtained < 0 or maximum <= 0:
            errors.append(f"Row {row_idx}: ❌ Invalid mark range")
            continue
        if obtained > maximum:
            errors.append(f"Row {row_idx}: ❌ Marks cannot exceed maximum marks")
            continue

        key = (code, sub_name.lower(), exam_name.lower())
        if key in seen_keys:
            errors.append(f"Row {row_idx}: ❌ Duplicate result detected")
            continue
        seen_keys.add(key)

        student = students.get(code)
        if not student:
            errors.append(f"Row {row_idx}: ❌ Student ID not found ({code})")
            continue
        subject = subjects.get(sub_name.lower())
        exam = exams.get(exam_name.lower())
        if not subject or not exam:
            errors.append(f"Row {row_idx}: ❌ Unknown Subject or Exam")
            continue

        duplicate_db = (
            db.query(Mark)
            .filter(Mark.student_id == student.id, Mark.exam_id == exam.id, Mark.subject_id == subject.id)
            .first()
        )
        if duplicate_db:
            errors.append(f"Row {row_idx}: ❌ Duplicate result detected in database for {code}")
            continue

        to_insert.append(
            Mark(
                student_id=student.id,
                exam_id=exam.id,
                subject_id=subject.id,
                class_room_id=class_room_id,
                obtained_marks=obtained,
                max_marks=maximum,
                grade=compute_grade(obtained, maximum),
                remark=(row.get("Remark") or "").strip() or None,
                entered_by_teacher_id=teacher_id,
            )
        )

    if errors:
        raise HTTPException(status_code=422, detail={"imported": 0, "errors": errors})

    db.add_all(to_insert)
    db.add(AuditLog(actor_user_id=actor.id, action="BULK_UPLOAD_MARKS", summary=f"{actor.name} imported {len(to_insert)} marks."))
    db.commit()
    return {"imported": len(to_insert), "errors": []}
''',

    "backend/app/routers/attendance.py": r'''from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rbac import assert_teacher_authorized, require_roles
from app.models.models import Attendance, AuditLog, Role, User
from app.schemas.schemas import AttendanceBulkRequest

router = APIRouter(prefix="/api/attendance", tags=["Attendance"])


@router.post("/")
def record_attendance(
    payload: AttendanceBulkRequest,
    actor: User = Depends(require_roles(Role.TEACHER, Role.ADMIN)),
    db: Session = Depends(get_db),
):
    assert_teacher_authorized(db, actor, payload.class_room_id)
    for entry in payload.entries:
        existing = (
            db.query(Attendance)
            .filter(Attendance.student_id == entry.student_id, Attendance.date == payload.date)
            .first()
        )
        if existing:
            existing.status = entry.status
            existing.note = entry.note
        else:
            db.add(
                Attendance(
                    student_id=entry.student_id,
                    class_room_id=payload.class_room_id,
                    date=payload.date,
                    status=entry.status,
                    note=entry.note,
                )
            )
    db.add(AuditLog(actor_user_id=actor.id, action="RECORD_ATTENDANCE", summary=f"{actor.name} updated attendance for {payload.date}."))
    db.commit()
    return {"saved": len(payload.entries)}
''',

    "backend/app/routers/homework.py": r'''from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rbac import assert_teacher_authorized, require_roles
from app.models.models import Homework, Role, User
from app.schemas.schemas import HomeworkCreateRequest

router = APIRouter(prefix="/api/homework", tags=["Homework"])


@router.post("/")
def create_homework(
    payload: HomeworkCreateRequest,
    actor: User = Depends(require_roles(Role.TEACHER, Role.ADMIN)),
    db: Session = Depends(get_db),
):
    assert_teacher_authorized(db, actor, payload.class_room_id, payload.subject_id)
    hw = Homework(**payload.model_dump())
    db.add(hw)
    db.commit()
    db.refresh(hw)
    return {"id": hw.id, "title": hw.title}
''',

    "backend/app/main.py": r'''from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import Base, engine
from app.routers import attendance, auth, homework, marks, parent

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SchoolConnect API",
    description="Connecting School, Teachers & Parents — One Smart Dashboard.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(parent.router)
app.include_router(marks.router)
app.include_router(attendance.router)
app.include_router(homework.router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "SchoolConnect API"}
''',

    "backend/seed.py": r'''from datetime import date
from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password
from app.models.models import (
    Attendance,
    AttendanceStatus,
    ClassRoom,
    Enrollment,
    Exam,
    Homework,
    Mark,
    Notice,
    ParentProfile,
    ParentStudentLink,
    Priority,
    Role,
    StudentProfile,
    Subject,
    TeacherClassSubject,
    TeacherProfile,
    User,
)


def seed_database() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == "admin@demo.school").first():
            print("Demo data already seeded.")
            return

        pwd_hash = hash_password("Demo@1234")

        admin = User(email="admin@demo.school", password_hash=pwd_hash, role=Role.ADMIN, name="Principal Demo Admin")
        t_user = User(email="teacher@demo.school", password_hash=pwd_hash, role=Role.TEACHER, name="Teacher Rahul")
        p_user = User(email="parent@demo.school", password_hash=pwd_hash, role=Role.PARENT, name="Mr. Sharma")
        p2_user = User(email="parent2@demo.school", password_hash=pwd_hash, role=Role.PARENT, name="Mrs. Verma")
        s_user = User(email="student@demo.school", password_hash=pwd_hash, role=Role.STUDENT, name="Aarav Sharma")
        s2_user = User(email="student2@demo.school", password_hash=pwd_hash, role=Role.STUDENT, name="Riya Verma")

        db.add_all([admin, t_user, p_user, p2_user, s_user, s2_user])
        db.flush()

        teacher = TeacherProfile(user_id=t_user.id, employee_code="TCH-001")
        parent1 = ParentProfile(user_id=p_user.id)
        parent2 = ParentProfile(user_id=p2_user.id)
        student1 = StudentProfile(user_id=s_user.id, student_code="DPDS-2026-001")
        student2 = StudentProfile(user_id=s2_user.id, student_code="DPDS-2026-002")
        db.add_all([teacher, parent1, parent2, student1, student2])
        db.flush()

        db.add_all([
            ParentStudentLink(parent_id=parent1.id, student_id=student1.id),
            ParentStudentLink(parent_id=parent2.id, student_id=student2.id),
        ])

        cls_10a = ClassRoom(display_name="10-A", class_teacher_id=teacher.id)
        math = Subject(code="MATH", name="Mathematics")
        sci = Subject(code="SCI", name="Science")
        db.add_all([cls_10a, math, sci])
        db.flush()

        db.add_all([
            TeacherClassSubject(teacher_id=teacher.id, class_room_id=cls_10a.id, subject_id=math.id),
            TeacherClassSubject(teacher_id=teacher.id, class_room_id=cls_10a.id, subject_id=sci.id),
            Enrollment(student_id=student1.id, class_room_id=cls_10a.id, roll_number=1),
            Enrollment(student_id=student2.id, class_room_id=cls_10a.id, roll_number=2),
        ])

        exam = Exam(name="Mid-Term 2026", start_date=date(2026, 11, 10))
        db.add(exam)
        db.flush()

        db.add_all([
            Mark(student_id=student1.id, exam_id=exam.id, subject_id=math.id, class_room_id=cls_10a.id, obtained_marks=87, max_marks=100, grade="A", remark="Strong improvement", entered_by_teacher_id=teacher.id),
            Mark(student_id=student1.id, exam_id=exam.id, subject_id=sci.id, class_room_id=cls_10a.id, obtained_marks=91, max_marks=100, grade="A+", entered_by_teacher_id=teacher.id),
            Attendance(student_id=student1.id, class_room_id=cls_10a.id, date=date(2026, 11, 18), status=AttendanceStatus.PRESENT),
            Homework(title="Chapter 4 — Quadratic Equations", description="Complete Questions 1–10.", class_room_id=cls_10a.id, subject_id=math.id, due_date=date(2026, 11, 22), priority=Priority.HIGH),
            Notice(title="PTM Announcement", description="Parent-Teacher Meeting this Saturday at 9:30 AM.", is_pinned=True, is_important=True),
        ])

        db.commit()
        print("Seeded SchoolConnect database! Demo password for all accounts: Demo@1234")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
''',

    "backend/tests/test_rbac_and_marks.py": r'''import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.schemas import MarkEntryRequest
from seed import seed_database


@pytest.fixture(scope="session", autouse=True)
def setup_seed():
    seed_database()


client = TestClient(app)


def login_token(email: str, password: str = "Demo@1234") -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_marks_bounds_validation():
    with pytest.raises(ValueError, match="Marks cannot exceed maximum marks"):
        MarkEntryRequest(
            student_id="s1",
            exam_id="e1",
            subject_id="sub1",
            class_room_id="c1",
            obtained_marks=105,
            max_marks=100,
        )


def test_parent_cannot_access_other_parents_child():
    parent1_token = login_token("parent@demo.school")
    parent2_token = login_token("parent2@demo.school")

    p2_overview = client.get("/api/parent/overview", headers={"Authorization": f"Bearer {parent2_token}"})
    assert p2_overview.status_code == 200
    other_child_id = p2_overview.json()["active_child"]["id"]

    attempt = client.get(
        f"/api/parent/overview?student_id={other_child_id}",
        headers={"Authorization": f"Bearer {parent1_token}"},
    )
    assert attempt.status_code == 403
''',
}


def main() -> None:
    root = Path.cwd()
    for rel_path, content in FILES.items():
        file_path = root / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")

    zip_path = root / "schoolconnect-backend.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in FILES:
            zf.write(root / rel_path, arcname=rel_path)

    print(f"Created {len(FILES)} files inside: {root / 'backend'}")
    print(f"Created ZIP archive: {zip_path}")


if __name__ == "__main__":
    main()
