from __future__ import annotations

import asyncio
import os
import secrets
import base64
import hashlib
import hmac
import json
import time as time_module
from contextlib import asynccontextmanager, suppress
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import (
    Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, func, or_, select
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./subscription_billing.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-this-secret-before-deploying")
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "720"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
REMINDER_DAYS = int(os.getenv("REMINDER_DAYS", "3"))

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
bearer = HTTPBearer(auto_error=False)



def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def hash_password(password: str) -> str:
    iterations = 310_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${b64url(salt)}${b64url(digest)}"

def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations_text, salt_text, digest_text = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        calculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), unb64url(salt_text), int(iterations_text))
        return hmac.compare_digest(calculated, unb64url(digest_text))
    except (ValueError, TypeError):
        return False

def encode_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = b64url(json.dumps(header, separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    signature = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{head}.{body}.{b64url(signature)}"

def decode_token(token: str) -> dict:
    try:
        head, body, signature = token.split(".", 2)
        header = json.loads(unb64url(head))
        if header.get("alg") != "HS256":
            raise ValueError("Unsupported token algorithm")
        signing_input = f"{head}.{body}".encode("ascii")
        expected = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, unb64url(signature)):
            raise ValueError("Invalid token signature")
        payload = json.loads(unb64url(body))
        if int(payload.get("exp", 0)) <= int(time_module.time()):
            raise ValueError("Token expired")
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid or expired token") from exc

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def money_to_cents(value: Decimal | int | float | str) -> int:
    amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if amount < 0:
        raise ValueError("Amount cannot be negative")
    return int(amount * 100)


def cents_to_money(cents: int) -> str:
    return f"{Decimal(cents) / Decimal(100):.2f}"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="staff", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    company: Mapped[Optional[str]] = mapped_column(String(160), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class Plan(Base):
    __tablename__ = "plans"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    billing_interval: Mapped[str] = mapped_column(String(20), nullable=False)  # monthly/yearly
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True, nullable=False)
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="Pending", nullable=False, index=True)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    customer: Mapped[Customer] = relationship()
    plan: Mapped[Plan] = relationship()


class Invoice(Base):
    __tablename__ = "invoices"
    __table_args__ = (UniqueConstraint("subscription_id", "period_start", name="uq_invoice_subscription_period"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"), index=True, nullable=False)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), index=True, nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    period_end: Mapped[date] = mapped_column(Date, nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="Pending", nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    subscription: Mapped[Subscription] = relationship()
    customer: Mapped[Customer] = relationship()


class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(primary_key=True)
    payment_ref: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), unique=True, nullable=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True, nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    method: Mapped[str] = mapped_column(String(40), default="simulated", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    invoice: Mapped[Invoice] = relationship()


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class Reminder(Base):
    __tablename__ = "reminders"
    __table_args__ = (UniqueConstraint("subscription_id", "reminder_date", "kind", name="uq_reminder_once"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"), index=True, nullable=False)
    reminder_date: Mapped[date] = mapped_column(Date, nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    message: Mapped[str] = mapped_column(String(255), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class RegisterInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class StaffCreateInput(RegisterInput):
    role: str = Field(default="staff", pattern="^(admin|staff)$")


class CustomerInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: EmailStr
    company: Optional[str] = Field(default=None, max_length=160)
    phone: Optional[str] = Field(default=None, max_length=40)


class PlanInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=2000)
    price: Decimal = Field(gt=0, max_digits=10, decimal_places=2)
    billing_interval: str = Field(pattern="^(monthly|yearly)$")
    is_active: bool = True

    @field_validator("price")
    @classmethod
    def validate_price(cls, value: Decimal) -> Decimal:
        if value <= 0:
            raise ValueError("Price must be greater than zero")
        return value


class SubscriptionInput(BaseModel):
    customer_id: int
    plan_id: int
    start_date: Optional[date] = None


class PlanChangeInput(BaseModel):
    plan_id: int


class PaymentSimulationInput(BaseModel):
    success: bool = True
    method: str = Field(default="simulated", pattern="^(simulated|cash|bank_transfer)$")


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    email: str
    role: str
    is_active: bool


# API serialization helpers
def customer_out(c: Customer) -> dict:
    return {"id": c.id, "name": c.name, "email": c.email, "company": c.company, "phone": c.phone,
            "created_at": c.created_at.isoformat()}


def plan_out(p: Plan) -> dict:
    return {"id": p.id, "name": p.name, "description": p.description, "price": cents_to_money(p.price_cents),
            "price_cents": p.price_cents, "billing_interval": p.billing_interval, "is_active": p.is_active,
            "created_at": p.created_at.isoformat()}


def subscription_out(s: Subscription) -> dict:
    return {"id": s.id, "customer_id": s.customer_id, "customer_name": s.customer.name,
            "plan_id": s.plan_id, "plan_name": s.plan.name, "plan_price": cents_to_money(s.plan.price_cents),
            "billing_interval": s.plan.billing_interval, "status": s.status,
            "start_date": s.start_date.isoformat(), "end_date": s.end_date.isoformat(),
            "days_remaining": max((s.end_date - date.today()).days, 0), "created_at": s.created_at.isoformat()}


def invoice_out(i: Invoice) -> dict:
    return {"id": i.id, "invoice_number": i.invoice_number, "subscription_id": i.subscription_id,
            "customer_id": i.customer_id, "customer_name": i.customer.name, "period_start": i.period_start.isoformat(),
            "period_end": i.period_end.isoformat(), "amount": cents_to_money(i.amount_cents),
            "amount_cents": i.amount_cents, "status": i.status, "issued_at": i.issued_at.isoformat(),
            "due_at": i.due_at.isoformat()}


def payment_out(p: Payment) -> dict:
    return {"id": p.id, "payment_ref": p.payment_ref, "invoice_id": p.invoice_id,
            "invoice_number": p.invoice.invoice_number, "customer_name": p.invoice.customer.name,
            "amount": cents_to_money(p.amount_cents), "status": p.status, "method": p.method,
            "created_at": p.created_at.isoformat()}


def log_action(db: Session, actor_id: Optional[int], entity_type: str, entity_id: int, action: str, details: str = "") -> None:
    db.add(ActivityLog(actor_id=actor_id, entity_type=entity_type, entity_id=entity_id, action=action, details=details))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(user: User) -> str:
    now = utcnow()
    return encode_token({"sub": str(user.id), "role": user.role, "iat": int(now.timestamp()),
                         "exp": int((now + timedelta(minutes=ACCESS_TOKEN_MINUTES)).timestamp())})


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        payload = decode_token(credentials.credentials)
        user_id = int(payload.get("sub", "0"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account not found or inactive")
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dependency


def add_months(start: date, months: int) -> date:
    month_index = start.month - 1 + months
    year = start.year + month_index // 12
    month = month_index % 12 + 1
    import calendar
    day = min(start.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def create_invoice(db: Session, subscription: Subscription, plan: Plan, period_start: date, period_end: date) -> Invoice:
    existing = db.scalar(select(Invoice).where(
        Invoice.subscription_id == subscription.id, Invoice.period_start == period_start
    ))
    if existing:
        if existing.status != "Paid":
            existing.amount_cents = plan.price_cents
            existing.period_end = period_end
        return existing
    invoice = Invoice(
        invoice_number=f"INV-{utcnow():%Y%m%d}-{uuid4().hex[:8].upper()}",
        subscription_id=subscription.id, customer_id=subscription.customer_id,
        period_start=period_start, period_end=period_end,
        amount_cents=plan.price_cents, status="Pending", issued_at=utcnow(),
        due_at=utcnow() + timedelta(days=7)
    )
    db.add(invoice)
    db.flush()
    return invoice


def ensure_admin(db: Session) -> None:
    existing = db.scalar(select(User).where(User.email == ADMIN_EMAIL))
    if not existing:
        db.add(User(name="System Admin", email=ADMIN_EMAIL,
                    password_hash=hash_password(ADMIN_PASSWORD), role="admin", is_active=True))
        db.commit()


def run_subscription_maintenance() -> None:
    """Mark subscriptions expired and create one renewal reminder per period."""
    db = SessionLocal()
    try:
        today = date.today()
        expiring = db.scalars(select(Subscription).where(
            Subscription.status == "Active", Subscription.end_date <= today
        )).all()
        for sub in expiring:
            sub.status = "Expired"
            log_action(db, None, "subscription", sub.id, "expired", "Automatically expired by scheduler")
        upcoming = db.scalars(select(Subscription).where(
            Subscription.status == "Active",
            Subscription.end_date > today,
            Subscription.end_date <= today + timedelta(days=REMINDER_DAYS)
        )).all()
        for sub in upcoming:
            existing = db.scalar(select(Reminder).where(
                Reminder.subscription_id == sub.id,
                Reminder.reminder_date == sub.end_date,
                Reminder.kind == "renewal"
            ))
            if not existing:
                db.add(Reminder(subscription_id=sub.id, reminder_date=sub.end_date, kind="renewal",
                                message=f"Subscription #{sub.id} renews on {sub.end_date.isoformat()}"))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def maintenance_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(run_subscription_maintenance)
        except Exception as exc:
            print(f"Subscription maintenance error: {exc}")
        await asyncio.sleep(60 * 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_admin(db)
        if not db.scalar(select(Plan.id).limit(1)):
            db.add_all([
                Plan(name="Starter Monthly", description="Monthly starter subscription", price_cents=1900, billing_interval="monthly", is_active=True),
                Plan(name="Business Monthly", description="Monthly business subscription", price_cents=4900, billing_interval="monthly", is_active=True),
                Plan(name="Business Yearly", description="Annual business subscription", price_cents=49900, billing_interval="yearly", is_active=True),
            ])
            db.commit()
    task = asyncio.create_task(maintenance_loop())
    yield
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="Subscription & Billing Management System", version="1.0.0", lifespan=lifespan)
@app.get("/", include_in_schema=False)
def root():
    return {"service": "Subscription & Billing Management API", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "subscription-billing-system"}


@app.post("/auth/login")
def login(data: LoginInput, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": UserOut.model_validate(user).model_dump()}


@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@app.post("/staff", status_code=201, response_model=UserOut)
def create_staff(data: StaffCreateInput, db: Session = Depends(get_db), admin: User = Depends(require_roles("admin"))):
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(name=data.name, email=email, password_hash=hash_password(data.password), role=data.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, admin.id, "user", user.id, "created", f"Role: {user.role}")
    db.commit()
    return user


@app.get("/staff", response_model=list[UserOut])
def list_staff(db: Session = Depends(get_db), admin: User = Depends(require_roles("admin"))):
    return db.scalars(select(User).order_by(User.id)).all()


@app.post("/customers", status_code=201)
def create_customer(data: CustomerInput, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    customer = Customer(name=data.name.strip(), email=data.email.lower(), company=data.company, phone=data.phone)
    db.add(customer)
    db.commit()
    db.refresh(customer)
    log_action(db, user.id, "customer", customer.id, "created")
    db.commit()
    return customer_out(customer)


@app.get("/customers")
def list_customers(search: Optional[str] = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                   db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    query = select(Customer)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(Customer.name.ilike(term), Customer.email.ilike(term), Customer.company.ilike(term)))
    return [customer_out(c) for c in db.scalars(query.order_by(Customer.id.desc()).offset(offset).limit(limit)).all()]


@app.get("/customers/{customer_id}")
def get_customer(customer_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    customer = db.get(Customer, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer_out(customer)


@app.put("/customers/{customer_id}")
def update_customer(customer_id: int, data: CustomerInput, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    customer = db.get(Customer, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    customer.name, customer.email = data.name.strip(), data.email.lower()
    customer.company, customer.phone = data.company, data.phone
    db.commit()
    log_action(db, user.id, "customer", customer.id, "updated")
    db.commit()
    return customer_out(customer)


@app.post("/plans", status_code=201)
def create_plan(data: PlanInput, db: Session = Depends(get_db), admin: User = Depends(require_roles("admin"))):
    if db.scalar(select(Plan).where(func.lower(Plan.name) == data.name.lower())):
        raise HTTPException(status_code=409, detail="Plan name already exists")
    plan = Plan(name=data.name.strip(), description=data.description, price_cents=money_to_cents(data.price),
                billing_interval=data.billing_interval, is_active=data.is_active)
    db.add(plan)
    db.commit()
    db.refresh(plan)
    log_action(db, admin.id, "plan", plan.id, "created")
    db.commit()
    return plan_out(plan)


@app.get("/plans")
def list_plans(include_inactive: bool = False, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    query = select(Plan)
    if not include_inactive:
        query = query.where(Plan.is_active.is_(True))
    return [plan_out(p) for p in db.scalars(query.order_by(Plan.price_cents)).all()]


@app.put("/plans/{plan_id}")
def update_plan(plan_id: int, data: PlanInput, db: Session = Depends(get_db), admin: User = Depends(require_roles("admin"))):
    plan = db.get(Plan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    duplicate = db.scalar(select(Plan).where(func.lower(Plan.name) == data.name.lower(), Plan.id != plan_id))
    if duplicate:
        raise HTTPException(status_code=409, detail="Another plan already uses this name")
    plan.name, plan.description = data.name.strip(), data.description
    plan.price_cents, plan.billing_interval, plan.is_active = money_to_cents(data.price), data.billing_interval, data.is_active
    db.commit()
    log_action(db, admin.id, "plan", plan.id, "updated")
    db.commit()
    return plan_out(plan)


@app.post("/subscriptions", status_code=201)
def create_subscription(data: SubscriptionInput, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    customer, plan = db.get(Customer, data.customer_id), db.get(Plan, data.plan_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if not plan or not plan.is_active:
        raise HTTPException(status_code=404, detail="Active plan not found")
    start = data.start_date or date.today()
    end = add_months(start, 1 if plan.billing_interval == "monthly" else 12)
    sub = Subscription(customer_id=customer.id, plan_id=plan.id, status="Pending", start_date=start, end_date=end)
    db.add(sub)
    db.flush()
    invoice = create_invoice(db, sub, plan, start, end)
    log_action(db, user.id, "subscription", sub.id, "created", f"Invoice {invoice.invoice_number} generated")
    db.commit()
    db.refresh(sub)
    return {"subscription": subscription_out(sub), "invoice": invoice_out(invoice)}


@app.get("/subscriptions")
def list_subscriptions(search: Optional[str] = None, subscription_status: Optional[str] = None,
                       plan_id: Optional[int] = None, customer_id: Optional[int] = None,
                       limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                       db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    query = select(Subscription).join(Customer).join(Plan)
    if subscription_status:
        if subscription_status not in {"Pending", "Active", "Cancelled", "Expired"}:
            raise HTTPException(status_code=400, detail="Invalid subscription status")
        query = query.where(Subscription.status == subscription_status)
    if plan_id:
        query = query.where(Subscription.plan_id == plan_id)
    if customer_id:
        query = query.where(Subscription.customer_id == customer_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(Customer.name.ilike(term), Customer.email.ilike(term), Plan.name.ilike(term)))
    items = db.scalars(query.order_by(Subscription.end_date).offset(offset).limit(limit)).all()
    return [subscription_out(s) for s in items]


@app.post("/subscriptions/{subscription_id}/activate")
def activate_subscription(subscription_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    sub = db.get(Subscription, subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.status == "Cancelled":
        raise HTTPException(status_code=409, detail="Cancelled subscription cannot be activated")
    if sub.end_date <= date.today():
        raise HTTPException(status_code=400, detail="Subscription period has already ended")
    sub.status = "Active"
    log_action(db, user.id, "subscription", sub.id, "activated")
    db.commit()
    return subscription_out(sub)


@app.post("/subscriptions/{subscription_id}/cancel")
def cancel_subscription(subscription_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    sub = db.get(Subscription, subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.status in {"Cancelled", "Expired"}:
        raise HTTPException(status_code=409, detail=f"Subscription is already {sub.status.lower()}")
    sub.status = "Cancelled"
    log_action(db, user.id, "subscription", sub.id, "cancelled")
    db.commit()
    return subscription_out(sub)


@app.post("/subscriptions/{subscription_id}/renew", status_code=201)
def renew_subscription(subscription_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    sub = db.get(Subscription, subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.status == "Cancelled":
        raise HTTPException(status_code=409, detail="Cancelled subscriptions cannot be renewed; create a new subscription")
    plan = db.get(Plan, sub.plan_id)
    if sub.status == "Pending":
        raise HTTPException(status_code=409, detail="Pay the current invoice before creating a renewal")
    start = max(sub.end_date, date.today())
    end = add_months(start, 1 if plan.billing_interval == "monthly" else 12)
    invoice = create_invoice(db, sub, plan, start, end)
    log_action(db, user.id, "subscription", sub.id, "renewal_invoice_created", f"Invoice {invoice.invoice_number}")
    db.commit()
    return {"subscription": subscription_out(sub), "invoice": invoice_out(invoice)}


@app.post("/subscriptions/{subscription_id}/change-plan")
def change_subscription_plan(subscription_id: int, data: PlanChangeInput, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    sub, plan = db.get(Subscription, subscription_id), db.get(Plan, data.plan_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if not plan or not plan.is_active:
        raise HTTPException(status_code=404, detail="Active plan not found")
    if sub.status in {"Cancelled", "Expired"}:
        raise HTTPException(status_code=409, detail="Cannot change plan for cancelled or expired subscription")
    current_invoice = db.scalar(select(Invoice).where(
        Invoice.subscription_id == sub.id, Invoice.period_start == sub.start_date
    ))
    sub.plan_id = plan.id
    if current_invoice and current_invoice.status != "Paid":
        current_invoice.amount_cents = plan.price_cents
        current_invoice.period_end = sub.end_date
        invoice = current_invoice
    else:
        next_start = sub.end_date
        next_end = add_months(next_start, 1 if plan.billing_interval == "monthly" else 12)
        invoice = create_invoice(db, sub, plan, next_start, next_end)
        if invoice.status == "Paid":
            raise HTTPException(status_code=409, detail="The next billing period is already paid; plan change cannot be billed twice")
    log_action(db, user.id, "subscription", sub.id, "plan_changed", f"Changed to {plan.name}; invoice {invoice.invoice_number}")
    db.commit()
    return {"subscription": subscription_out(sub), "invoice": invoice_out(invoice)}


@app.get("/invoices")
def list_invoices(invoice_status: Optional[str] = None, search: Optional[str] = None,
                  db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    query = select(Invoice).join(Customer)
    if invoice_status:
        if invoice_status not in {"Pending", "Paid", "Failed"}:
            raise HTTPException(status_code=400, detail="Invalid invoice status")
        query = query.where(Invoice.status == invoice_status)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(Invoice.invoice_number.ilike(term), Customer.name.ilike(term), Customer.email.ilike(term)))
    return [invoice_out(i) for i in db.scalars(query.order_by(Invoice.issued_at.desc())).all()]


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    invoice = db.get(Invoice, invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice_out(invoice)


@app.get("/invoices/{invoice_id}/print", response_class=HTMLResponse)
def print_invoice(invoice_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    invoice = db.get(Invoice, invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    customer, sub, plan = invoice.customer, invoice.subscription, invoice.subscription.plan
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{invoice.invoice_number}</title>
    <style>body{{font-family:Arial,sans-serif;max-width:760px;margin:40px auto;padding:24px;color:#182230}}h1{{margin-bottom:4px}}.muted{{color:#667085}}table{{width:100%;border-collapse:collapse;margin-top:24px}}td,th{{padding:12px;border-bottom:1px solid #ddd;text-align:left}}.total{{text-align:right;font-size:22px;font-weight:bold;margin-top:24px}}button{{padding:10px 16px;margin-top:20px}}@media print{{button{{display:none}}}}</style></head><body>
    <h1>INVOICE</h1><div class='muted'>Subscription & Billing Management System</div><hr>
    <p><b>Invoice:</b> {invoice.invoice_number}<br><b>Issued:</b> {invoice.issued_at:%Y-%m-%d}<br><b>Due:</b> {invoice.due_at:%Y-%m-%d}<br><b>Status:</b> {invoice.status}</p>
    <h3>Bill to</h3><p>{customer.name}<br>{customer.email}<br>{customer.company or ''}</p>
    <table><tr><th>Description</th><th>Period</th><th>Amount</th></tr><tr><td>{plan.name}</td><td>{invoice.period_start} to {invoice.period_end}</td><td>{cents_to_money(invoice.amount_cents)}</td></tr></table>
    <div class='total'>Total: {cents_to_money(invoice.amount_cents)}</div><button onclick='window.print()'>Print invoice</button></body></html>"""


@app.post("/invoices/{invoice_id}/simulate-payment", status_code=201)
def simulate_payment(invoice_id: int, data: PaymentSimulationInput,
                    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
                    db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    invoice = db.get(Invoice, invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if idempotency_key:
        existing_by_key = db.scalar(select(Payment).where(Payment.idempotency_key == idempotency_key))
        if existing_by_key:
            if existing_by_key.invoice_id != invoice_id:
                raise HTTPException(status_code=409, detail="Idempotency key was already used for another invoice")
            return {"payment": payment_out(existing_by_key), "idempotent_replay": True}
    if invoice.status == "Paid":
        prior = db.scalar(select(Payment).where(Payment.invoice_id == invoice.id, Payment.status == "Paid"))
        if prior:
            return {"payment": payment_out(prior), "idempotent_replay": True}
        raise HTTPException(status_code=409, detail="Invoice is already paid")
    payment = Payment(payment_ref=f"PAY-{uuid4().hex[:12].upper()}", idempotency_key=idempotency_key,
                      invoice_id=invoice.id, amount_cents=invoice.amount_cents,
                      status="Paid" if data.success else "Failed", method=data.method)
    invoice.status = "Paid" if data.success else "Failed"
    sub = invoice.subscription
    if data.success:
        if invoice.period_start >= sub.end_date and invoice.period_start > sub.start_date:
            sub.start_date = invoice.period_start
            sub.end_date = invoice.period_end
            sub.status = "Active"
        elif sub.status == "Pending":
            sub.status = "Active"
    db.add(payment)
    log_action(db, user.id, "payment", invoice.id, payment.status.lower(), f"Invoice {invoice.invoice_number}")
    db.commit()
    db.refresh(payment)
    return {"payment": payment_out(payment), "idempotent_replay": False,
            "subscription": subscription_out(sub)}


@app.get("/payments")
def list_payments(payment_status: Optional[str] = None, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    query = select(Payment)
    if payment_status:
        if payment_status not in {"Pending", "Paid", "Failed"}:
            raise HTTPException(status_code=400, detail="Invalid payment status")
        query = query.where(Payment.status == payment_status)
    return [payment_out(p) for p in db.scalars(query.order_by(Payment.created_at.desc())).all()]


@app.get("/reminders")
def list_reminders(unread_only: bool = False, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    query = select(Reminder)
    if unread_only:
        query = query.where(Reminder.is_read.is_(False))
    reminders = db.scalars(query.order_by(Reminder.reminder_date)).all()
    return [{"id": r.id, "subscription_id": r.subscription_id, "reminder_date": r.reminder_date.isoformat(),
             "kind": r.kind, "message": r.message, "is_read": r.is_read, "created_at": r.created_at.isoformat()} for r in reminders]


@app.post("/reminders/{reminder_id}/read")
def mark_reminder_read(reminder_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    reminder = db.get(Reminder, reminder_id)
    if not reminder:
        raise HTTPException(status_code=404, detail="Reminder not found")
    reminder.is_read = True
    db.commit()
    return {"id": reminder.id, "is_read": reminder.is_read}


@app.get("/analytics")
def analytics(db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    total_customers = db.scalar(select(func.count(Customer.id))) or 0
    active_subscriptions = db.scalar(select(func.count(Subscription.id)).where(Subscription.status == "Active")) or 0
    pending_payments = db.scalar(select(func.count(Invoice.id)).where(Invoice.status == "Pending")) or 0
    paid_revenue = db.scalar(select(func.coalesce(func.sum(Payment.amount_cents), 0)).where(Payment.status == "Paid")) or 0
    today = date.today()
    month_start = today.replace(day=1)
    next_month = add_months(month_start, 1)
    monthly_revenue = db.scalar(select(func.coalesce(func.sum(Payment.amount_cents), 0)).where(
        Payment.status == "Paid", Payment.created_at >= datetime.combine(month_start, datetime.min.time()),
        Payment.created_at < datetime.combine(next_month, datetime.min.time())
    )) or 0
    monthly_rows = db.execute(select(func.strftime("%Y-%m", Payment.created_at), func.sum(Payment.amount_cents))
                              .where(Payment.status == "Paid").group_by(func.strftime("%Y-%m", Payment.created_at))
                              .order_by(func.strftime("%Y-%m", Payment.created_at))).all()
    growth_rows = db.execute(select(func.strftime("%Y-%m", Subscription.created_at), func.count(Subscription.id))
                              .group_by(func.strftime("%Y-%m", Subscription.created_at))
                              .order_by(func.strftime("%Y-%m", Subscription.created_at))).all()
    return {"total_customers": total_customers, "active_subscriptions": active_subscriptions,
            "pending_payments": pending_payments, "monthly_revenue": cents_to_money(int(monthly_revenue)),
            "total_paid_revenue": cents_to_money(int(paid_revenue)), "revenue_by_month": [{"month": month, "amount": cents_to_money(int(amount or 0))} for month, amount in monthly_rows],
            "subscriptions_by_month": [{"month": month, "count": int(count)} for month, count in growth_rows]}


@app.get("/activity")
def activity(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "staff"))):
    rows = db.scalars(select(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(limit)).all()
    return [{"id": r.id, "actor_id": r.actor_id, "entity_type": r.entity_type, "entity_id": r.entity_id,
             "action": r.action, "details": r.details, "created_at": r.created_at.isoformat()} for r in rows]


@app.post("/admin/run-maintenance")
def manual_maintenance(db: Session = Depends(get_db), admin: User = Depends(require_roles("admin"))):
    run_subscription_maintenance()
    return {"status": "maintenance_completed", "checked_at": utcnow().isoformat()}
